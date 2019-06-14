all:  sender receiver

.PHONY: sender receiver clean

clean: clean_sender clean_receiver


sender: 
	@echo Building client
	make all -C Client
	@cd bin && ln -sf ../Client/client

receiver: 
	@echo Building server
	make all -C Server	
	@cd bin && ln -sf ../Server/server

clean_sender:
	make clean -C Client


clean_receiver:
	make clean -C Server

