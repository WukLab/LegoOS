Build in current source tree:
  ```
  $ make config
  $ make
  ```

Build to another directory, e.g. if you want to compile all files into a
directory named build/ under current source tree, you can:
  ```
  $ pwd
  /../LegoOS
  $ make config O=build		# this will put .config into build/
  $ make all O=build
  ```

To install the compiled image, simply type:
  ```
  $ make install
  ```
The image will be installed into `/boot` directory as a regular linux kernel.

For mor information, type `make help`.
