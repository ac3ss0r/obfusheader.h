@echo off
echo Running tests...
call :run_test "./tests/output.cpp"
call :run_test "./tests/call_hiding.cpp"
pause
exit

:run_test
echo Building %~1 with gcc...
gcc %~1 -O3 -fPIC -march=native -o "test_current.exe"
echo Executing...
"test_current"
echo Building %~1 with g++...
g++ %~1 -O3 -fPIC -march=native -o "test_current.exe"
echo Executing...
"test_current"
del test_current.exe
goto:eof