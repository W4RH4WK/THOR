.PHONY: clean

getroot: main.c
	gcc -o getroot main.c
	sudo chown root:root getroot
	sudo chmod 4755 getroot

clean:
	sudo rm -f getroot
