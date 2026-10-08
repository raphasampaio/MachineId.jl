@echo off

SET BASE_PATH=%~dp0

CALL julia --project=%BASE_PATH%\.. -e "import Pkg; Pkg.test(test_args=ARGS)" -- %*