# Makefile for Enhanced Double Ratchet Implementation

# Python interpreter
PYTHON := python
PIP := pip

# Project directories
SRC_DIR := src
TEST_DIR := tests
EXAMPLES_DIR := examples
TOOLS_DIR := tools

# Virtual environment
VENV_DIR := venv
VENV_BIN := $(VENV_DIR)/Scripts
VENV_PYTHON := $(VENV_BIN)/python.exe
VENV_PIP := $(VENV_BIN)/pip.exe

.PHONY: help install install-dev test clean demo run-tests lint format setup-venv

# Default target
help:
	@echo "Enhanced Double Ratchet Implementation - Make Commands"
	@echo "=================================================="
	@echo ""
	@echo "Setup Commands:"
	@echo "  make setup-venv      Create virtual environment"
	@echo "  make install         Install package dependencies"
	@echo "  make install-dev     Install with development dependencies"
	@echo ""
	@echo "Development Commands:"
	@echo "  make test            Run test suite"
	@echo "  make lint            Run code linting"
	@echo "  make format          Format code with black"
	@echo "  make demo            Run demonstration"
	@echo ""
	@echo "Server Commands:"
	@echo "  make run-server      Start enhanced server"
	@echo "  make run-alice       Start Alice client"
	@echo "  make run-bob         Start Bob client"
	@echo "  make run-malory      Start Malory cryptanalysis tool"
	@echo ""
	@echo "Cleanup Commands:"
	@echo "  make clean           Clean build artifacts and cache files"
	@echo "  make clean-states    Clean saved ratchet states"

# Setup virtual environment
setup-venv:
	@echo "Creating virtual environment..."
	$(PYTHON) -m venv $(VENV_DIR)
	@echo "Virtual environment created at $(VENV_DIR)"
	@echo "Activate with: $(VENV_DIR)\\Scripts\\activate"

# Install dependencies
install:
	$(PIP) install -r requirements.txt

install-dev: install
	$(PIP) install -e .[dev]

# Testing
test:
	@echo "Running test suite..."
	$(PYTHON) $(TEST_DIR)/test_enhanced_features.py

run-tests: test

# Linting and formatting (if dev dependencies are installed)
lint:
	@echo "Running linting..."
	-flake8 $(SRC_DIR) $(TEST_DIR) $(EXAMPLES_DIR) $(TOOLS_DIR)
	-mypy $(SRC_DIR)

format:
	@echo "Formatting code..."
	-black $(SRC_DIR) $(TEST_DIR) $(EXAMPLES_DIR) $(TOOLS_DIR)

# Demonstrations
demo:
	@echo "Running enhanced system demonstration..."
	$(PYTHON) $(EXAMPLES_DIR)/demo_enhanced_system.py

demo-simple:
	@echo "Running simple working demonstration..."
	$(PYTHON) $(EXAMPLES_DIR)/demo_simple_working.py

# Run individual components
run-server:
	@echo "Starting Enhanced Server..."
	$(PYTHON) $(SRC_DIR)/network/enhanced_server.py

run-alice:
	@echo "Starting Alice Client..."
	$(PYTHON) $(SRC_DIR)/network/enhanced_alice.py

run-bob:
	@echo "Starting Bob Client..."
	$(PYTHON) $(SRC_DIR)/network/enhanced_bob.py

run-malory:
	@echo "Starting Malory Cryptanalysis Tool..."
	$(PYTHON) $(TOOLS_DIR)/enhanced_malory.py

# Cleanup
clean:
	@echo "Cleaning build artifacts..."
	-rmdir /s /q __pycache__ 2>nul
	-rmdir /s /q .pytest_cache 2>nul
	-rmdir /s /q build 2>nul
	-rmdir /s /q dist 2>nul
	-rmdir /s /q *.egg-info 2>nul
	-for /r . %%d in (__pycache__) do @if exist "%%d" rmdir /s /q "%%d" 2>nul
	-del /s *.pyc 2>nul
	@echo "Cleanup complete."

clean-states:
	@echo "Cleaning saved ratchet states..."
	-rmdir /s /q ratchet_states 2>nul
	@echo "Ratchet states cleaned."

# Build distribution
build:
	$(PYTHON) setup.py sdist bdist_wheel

# Install in development mode
install-editable:
	$(PIP) install -e .

# Run all checks
check: lint test
	@echo "All checks completed."

# Development workflow
dev-setup: setup-venv install-dev
	@echo "Development environment setup complete."
	@echo "Activate virtual environment with: $(VENV_DIR)\\Scripts\\activate"

# Quick start for new users
quickstart: install demo
	@echo "Quick start complete! Enhanced Double Ratchet demo has been run."
	@echo "Try: make run-server (in one terminal), make run-bob (in another), make run-alice (in third)"