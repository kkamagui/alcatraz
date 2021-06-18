#
# Makefile for Hyper-box project.
#
all: hyper_box_module hyper_box_helper_module 
.ONESHELL:
hyper_box_module: 
	@echo 
	@echo ==================================
	@echo Build Hyper-Box Module
	@echo ==================================
	cd hyper_box
	make -j
	cd ..

hyper_box_helper_module:
	@echo 
	@echo ==================================
	@echo Build Hyper-Box Helper Module
	@echo ==================================
	cd hyper_box_helper
	make -j
	cd ..

clean:
	make -C hyper_box clean
	make -C hyper_box_helper clean
