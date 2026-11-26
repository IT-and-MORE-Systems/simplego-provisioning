# Device output fixtures

Text fixtures for the adb and fastboot parsers, in the output format of adb
and fastboot 37.0.1. Serials are masked (`XXXXXXXXXX` plus two characters).

- `getprop-pixel.txt`: synthetic. Build and boot properties written by hand
  in the real format for a Pixel 8 (shiba) on a GrapheneOS-style release
  number with a locked bootloader. No value comes from a real phone.
- The other files are also written by hand in the real format. No test device in
  fastboot mode, unauthorized or offline state was captured yet; replace them
  with real captures (serials masked) once our test devices are on USB.
