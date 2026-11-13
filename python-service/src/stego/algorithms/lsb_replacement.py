from .base import Algorithm, channels_of, from_bits


class LsbReplacement(Algorithm):
    variant = "lsb-replacement-msb-first-v1 (patch samples, raster order)"
    domain = "spatial (LSB plane)"
    reference = "Classic LSB replacement; e.g. Fridrich, Steganography in Digital Media, CUP 2009, ch. 5"
    id = 1
    name = "lsb_replacement"

    def capacity_bits(self, img, region, param=0):
        return region.n_pixels * channels_of(img)

    def embed(self, ctx, region, out, payload, param=0):
        p, bits, cap = self._need(ctx.cover, region, payload, param, out)
        idx = region.samples(ctx.channels)[:bits.size]
        flat = out.reshape(-1)
        flat[idx] = (flat[idx] & 0xFE) | bits
        return {"carriers_used": int(bits.size)}

    def extract(self, img, region, nbytes, param=0):
        self._check_extract(img, region, nbytes, self.resolve_param(param))
        idx = region.samples(channels_of(img))[:nbytes * 8]
        return from_bits(img.reshape(-1)[idx] & 1, nbytes)
