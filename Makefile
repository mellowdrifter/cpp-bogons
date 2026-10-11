CXX ?= g++
CXXFLAGS ?= -O3 -Wall -Wextra -pedantic -std=c++17
CPPFLAGS ?= -Iinclude
PREFIX ?= /usr/local
INCLUDEDIR ?= $(PREFIX)/include

all: test

tests/test_bogons: tests/test_bogons.cpp include/bogons/bogons.hpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) tests/test_bogons.cpp -o tests/test_bogons

test: tests/test_bogons
	./tests/test_bogons

install:
	install -d $(DESTDIR)$(INCLUDEDIR)/bogons
	install -m 644 include/bogons/bogons.hpp $(DESTDIR)$(INCLUDEDIR)/bogons/

clean:
	rm -f tests/test_bogons

.PHONY: all test clean install
