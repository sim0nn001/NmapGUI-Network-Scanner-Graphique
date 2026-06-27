CXX      := g++
CXXFLAGS := -std=c++17 -O2 -Wall

TARGET   := nmap_gui
SRC      := nmap_scanner.cpp

# Utilisation de pkg-config (IMPORTANT sur Arch)
GTK_FLAGS := $(shell pkg-config --cflags gtk+-3.0)
GTK_LIBS  := $(shell pkg-config --libs gtk+-3.0)

.PHONY: all clean run install-deps

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(GTK_FLAGS) -o $@ $< $(GTK_LIBS)
	@echo "✓ Compilation réussie → ./$(TARGET)"

install-deps:
	sudo pacman -S nmap gtk3 glib2 pango cairo atk gdk-pixbuf2 harfbuzz pkgconf base-devel

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)