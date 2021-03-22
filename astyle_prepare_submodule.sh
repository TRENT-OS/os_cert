#!/bin/bash -ue

#-------------------------------------------------------------------------------
# Copyright (C) 2021, HENSOLDT Cyber GmbH
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
# This script marks a submodule to be checked with astyle.
#
# The script has to set a variable ASTYLE_OPTIONS_SUBMODULE which is used by the
# astyle_check_submodule.sh script. Usually the variable is empty but it can be
# used to overwrite astyle options set in the default options file.
#
# Example:
# ASTYLE_OPTIONS_SUBMODULE="--max-code-length=200"
#-------------------------------------------------------------------------------

ASTYLE_OPTIONS_SUBMODULE=""
