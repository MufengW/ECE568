lab3: generateQRcode validateQRcode

generateQRcode: generateQRcode.c lib/encoding.o lib/bitstream.o lib/mask.o lib/mmask.o lib/mqrspec.o lib/qrencode.o lib/qrinput.o lib/qrspec.o lib/rsecc.o lib/split.o
	gcc -g  generateQRcode.c lib/encoding.o lib/bitstream.o lib/mask.o lib/mmask.o lib/mqrspec.o lib/qrencode.o lib/qrinput.o lib/qrspec.o lib/rsecc.o lib/split.o -o generateQRcode

validateQRcode: validateQRcode.c lib/sha1.o
	gcc -g validateQRcode.c lib/sha1.o -o validateQRcode

lib/encoding.o: lib/encoding.h lib/encoding.c
	gcc -g -c -std=gnu99 lib/encoding.c -o lib/encoding.o

lib/qrencode.o: lib/qrencode.c lib/qrencode.h lib/config.h
	gcc -g -c lib/qrencode.c -DHAVE_CONFIG_H -o lib/qrencode.o

lib/qrinput.o: lib/qrinput.h lib/qrinput.c lib/config.h
	gcc -g -c lib/qrinput.c -DHAVE_CONFIG_H -o lib/qrinput.o

lib/bitstream.o: lib/bitstream.h lib/bitstream.c
	gcc -g -c lib/bitstream.c -o lib/bitstream.o

lib/mqrspec.o: lib/mqrspec.h lib/mqrspec.c
	gcc -g -c lib/mqrspec.c -o lib/mqrspec.o

lib/rsecc.o: lib/rsecc.h lib/rsecc.c
	gcc -g -c lib/rsecc.c -o lib/rsecc.o

lib/split.o: lib/split.h lib/split.c
	gcc -g -c lib/split.c -o lib/split.o

lib/mask.o: lib/mask.h lib/mask.c lib/config.h
	gcc -g -c lib/mask.c -DHAVE_CONFIG_H -o lib/mask.o

lib/mmask.o: lib/mmask.h lib/mmask.c lib/config.h
	gcc -g -c lib/mmask.c -DHAVE_CONFIG_H -o lib/mmask.o

lib/qrspec.o: lib/qrspec.h lib/qrspec.c
	gcc -g -c lib/qrspec.c -o lib/qrspec.o

lib/sha1.o: lib/sha1.h lib/sha1.c
	gcc -g -c lib/sha1.c -o lib/sha1.o

clean:
	rm generateQRcode validateQRcode lib/*.o
