import zlib
from urllib.request import urlopen

from fpdf import FPDF
import base64, io, re

from fpdf.php import substr
from fpdf.py3k import PY3K, b


class PDF(FPDF):

    def _parsepng(self, name):
        # Extract info from a PNG file
        if name.startswith("http://") or name.startswith("https://"):
            f = urlopen(name)
        elif "data:image/png;base64" in name:
            f = name.split('base64,')[1]
            f = base64.b64decode(f)
            f = io.BytesIO(f)
        else:
            f = open(name, 'rb')
        if (not f):
            self.error("Can't open image file: " + name)
        # Check signature
        magic = f.read(8).decode("latin1")
        signature = '\x89' + 'PNG' + '\r' + '\n' + '\x1a' + '\n'
        if not PY3K: signature = signature.decode("latin1")
        if (magic != signature):
            self.error('Not a PNG file: ' + name)
        # Read header chunk
        f.read(4)
        chunk = f.read(4).decode("latin1")
        if (chunk != 'IHDR'):
            self.error('Incorrect PNG file: ' + name)
        w = self._freadint(f)
        h = self._freadint(f)
        bpc = ord(f.read(1))
        if (bpc > 8):
            self.error('16-bit depth not supported: ' + name)
        ct = ord(f.read(1))
        if (ct == 0 or ct == 4):
            colspace = 'DeviceGray'
        elif (ct == 2 or ct == 6):
            colspace = 'DeviceRGB'
        elif (ct == 3):
            colspace = 'Indexed'
        else:
            self.error('Unknown color type: ' + name)
        if (ord(f.read(1)) != 0):
            self.error('Unknown compression method: ' + name)
        if (ord(f.read(1)) != 0):
            self.error('Unknown filter method: ' + name)
        if (ord(f.read(1)) != 0):
            self.error('Interlacing not supported: ' + name)
        f.read(4)
        dp = '/Predictor 15 /Colors '
        if colspace == 'DeviceRGB':
            dp += '3'
        else:
            dp += '1'
        dp += ' /BitsPerComponent ' + str(bpc) + ' /Columns ' + str(w) + ''
        # Scan chunks looking for palette, transparency and image data
        pal = ''
        trns = ''
        data = bytes() if PY3K else str()
        n = 1
        while n != None:
            n = self._freadint(f)
            type = f.read(4).decode("latin1")
            if (type == 'PLTE'):
                # Read palette
                pal = f.read(n)
                f.read(4)
            elif (type == 'tRNS'):
                # Read transparency info
                t = f.read(n)
                if (ct == 0):
                    trns = [ord(substr(t, 1, 1)), ]
                elif (ct == 2):
                    trns = [ord(substr(t, 1, 1)), ord(substr(t, 3, 1)), ord(substr(t, 5, 1))]
                else:
                    pos = t.find('\x00'.encode("latin1"))
                    if (pos != -1):
                        trns = [pos, ]
                f.read(4)
            elif (type == 'IDAT'):
                # Read image data block
                data += f.read(n)
                f.read(4)
            elif (type == 'IEND'):
                break
            else:
                f.read(n + 4)
        if (colspace == 'Indexed' and not pal):
            self.error('Missing palette in ' + name)
        f.close()
        info = {'w': w, 'h': h, 'cs': colspace, 'bpc': bpc, 'f': 'FlateDecode', 'dp': dp, 'pal': pal, 'trns': trns, }
        if (ct >= 4):
            # Extract alpha channel
            data = zlib.decompress(data)
            color = b('')
            alpha = b('')
            if (ct == 4):
                # Gray image
                length = 2 * w
                for i in range(h):
                    pos = (1 + length) * i
                    color += b(data[pos])
                    alpha += b(data[pos])
                    line = substr(data, pos + 1, length)
                    re_c = re.compile('(.).'.encode("ascii"), flags=re.DOTALL)
                    re_a = re.compile('.(.)'.encode("ascii"), flags=re.DOTALL)
                    color += re_c.sub(lambda m: m.group(1), line)
                    alpha += re_a.sub(lambda m: m.group(1), line)
            else:
                # RGB image
                length = 4 * w
                for i in range(h):
                    pos = (1 + length) * i
                    color += b(data[pos])
                    alpha += b(data[pos])
                    line = substr(data, pos + 1, length)
                    re_c = re.compile('(...).'.encode("ascii"), flags=re.DOTALL)
                    re_a = re.compile('...(.)'.encode("ascii"), flags=re.DOTALL)
                    color += re_c.sub(lambda m: m.group(1), line)
                    alpha += re_a.sub(lambda m: m.group(1), line)
            del data
            data = zlib.compress(color)
            info['smask'] = zlib.compress(alpha)
            if (self.pdf_version < '1.4'):
                self.pdf_version = '1.4'
        info['data'] = data
        return info
