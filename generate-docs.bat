@echo off
set docs=..\docs\
rdmd bootDoc\generate.d .. --extra=%docs%index.d --modules=%docs%modules.ddoc --settings=%docs%settings.ddoc -I..\..\phobos-additions ||  pause
