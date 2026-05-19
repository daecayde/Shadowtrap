# Contributing to ShadowTrap

Thanks for your interest in contributing! Here's how to get started.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/yourusername/shadowtrap.git`
3. Create a branch: `git checkout -b feature/your-feature-name`
4. Install dev dependencies: `pip install -r requirements.txt`

## Development Guidelines

### Code Style
- Follow PEP 8
- Use type hints where possible
- Write docstrings for all public functions and classes
- Keep functions focused and under 50 lines where practical

### Adding a New Service

1. Create a new file in `shadowtrap/services/` (e.g., `dns_trap.py`)
2. Inherit from `BaseHoneypot` in `shadowtrap/services/base.py`
3. Implement the `start()` method returning an `asyncio.AbstractServer`
4. Register your service in `shadowtrap/core/engine.py` → `SERVICE_MAP`
5. Add configuration options to `config/shadowtrap.example.yml`
6. Write tests in `tests/`

### Testing

```bash
python -m pytest tests/ -v
```

### Commit Messages

Use conventional commits:
- `feat:` new features
- `fix:` bug fixes
- `docs:` documentation changes
- `refactor:` code refactoring
- `test:` adding or updating tests
- `chore:` maintenance tasks

## Pull Requests

1. Update documentation if needed
2. Add tests for new features
3. Ensure all tests pass
4. Submit a PR against the `main` branch
5. Describe what your PR does and why

## Reporting Issues

- Use GitHub Issues
- Include reproduction steps
- Include your OS, Python version, and relevant config

## Security

If you discover a security vulnerability, please report it privately via email instead of opening a public issue.

## Code of Conduct

Be respectful. We're all here to learn and build better security tools.
