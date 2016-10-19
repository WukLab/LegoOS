Build in current source tree:
  $ make config
  $ make

Build to another directory, e.g. if you want to compile all files into a
directory named build/, you can:
  $ pwd
  /../DisOS
  $ make config O=build		# this will put .config into build/
  $ make all O=build

For mor information, type 'make help'
