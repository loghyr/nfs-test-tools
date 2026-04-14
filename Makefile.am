# SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only

if HAVE_GSSAPI
SUBDIRS = src tests
else
SUBDIRS = src
endif

EXTRA_DIST = \
	README.md \
	CLAUDE.md \
	LICENSE

# -----------------------------------------------------------------------
# Style and static analysis targets (not wired into the normal build)
# -----------------------------------------------------------------------

CLANG_FORMAT ?= clang-format
CLANG_TIDY   ?= clang-tidy

# Check code style -- exits non-zero if any file needs reformatting.
style:
	@find src tests \( -name '*.[ch]' \) -print | \
		tr '\n' '\0' | xargs -0 $(CLANG_FORMAT) --dry-run -Werror

# Auto-fix style violations in-place.
fix-style:
	@find src tests \( -name '*.[ch]' \) -print | \
		tr '\n' '\0' | xargs -0 $(CLANG_FORMAT) -i

# Run clang-tidy against the build/ compile_commands.json.
# Requires 'bear -- make' to generate compile_commands.json first:
#   cd build && bear -- make && cd .. && make tidy
TIDY_CHECKS  ?= -checks='-*,clang-analyzer-*,bugprone-*,performance-*,readability-*,\
-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling'
tidy:
	@if [ ! -f build/compile_commands.json ]; then \
		echo "tidy: build/compile_commands.json not found."; \
		echo "  Run: cd build && bear -- make && cd .. && make tidy"; \
		exit 1; \
	fi
	@find src tests -name '*.c' -print | tr '\n' '\0' | \
		xargs -0 $(CLANG_TIDY) $(TIDY_CHECKS) \
		-p build/compile_commands.json

.PHONY: style fix-style tidy
