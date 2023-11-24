@echo off
echo Running tests...
call :build_and_run "gcc", "./tests/output.cpp"
call :build_and_run "g++", "./tests/output.cpp"
call :build_and_run "gcc", "./tests/call_hiding.cpp"
call :build_and_run "g++", "./tests/call_hiding.cpp"
pause
exit

:build_and_run
echo Building %~2 with %~1...
%~1 %~2 -O3 -fPIC -march=native -o test_current.exe
echo Executing %~2...
test_current
del test_current.exe
goto:eof