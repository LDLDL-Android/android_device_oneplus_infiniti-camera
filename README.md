# android_device_oneplus_infiniti-camera

Prebuilt stock oplus Camera to include in custom ROM builds.

### How to use?

1. Clone this repo to `device/oneplus/infiniti-camera`

2. Inherit it from `device.mk` in device tree:

```
# Camera
$(call inherit-product-if-exists, device/oneplus/infiniti-camera/opluscamera.mk)
```

3. Ensure that the PRODUCT_BRAND is either oneplus or oppo or realme and that it is not overriden by any of the safetynet hacks.

### How to extract proprietary files?

The fixups target OnePlus 15 `CPH2745_16.0.10.601(EX01)`, the build used by
the LineageOS infiniti/sm8850-common vendor trees. Other builds may move
obfuscated code; the fixups then stop with an error instead of silently
skipping.

The dump must contain one directory per partition (`system`, `system_ext`,
`product`, `vendor`, `odm`, `my_product`, `my_stock`, ...). For the
system-as-root `system` image, use its inner `system/` directory.

From the ROM source root, place or clone this repo at `device/oneplus/infiniti-camera`,
then run:

```
cd device/oneplus/infiniti-camera
./extract-files.py /path/to/OP15/dump
```

The extractor reads `proprietary-files.txt`, pulls the listed files from the
dump, applies the blob fixups in `extract-files.py`, and writes the results to:

```
vendor/oneplus/infiniti-camera/proprietary
```

It also regenerates the generated build files under:

```
vendor/oneplus/infiniti-camera
```

After changing `proprietary-files.txt`, rerun `./extract-files.py` against the
OP15 dump before building.
