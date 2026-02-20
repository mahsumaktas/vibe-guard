# 🛡️ Vibe-Guard Security Report

**Scan path:** `.`  
**Vibe Score:** 🔴 **15/100** — Unsafe
**Health:** 🟥🟥⬜⬜⬜⬜⬜⬜⬜⬜

### 📊 Summary
| Severity | Count |
|----------|-------|
| 🔴 Critical | 72 |
| 🟡 Warning | 379 |
| 🔵 Info | 5 |
| **Total** | **456** |

## 🔍 Detailed Findings

### 📄 `tests\test_hardcoded.py`

#### 🔴 Line 6: Hardcoded API key
```python
f.write('API_KEY = "a_very_long_and_secretive_api_key_string"\n')
```
> 💡 **Fix:** Move to environment variable or secrets manager

#### 🔴 Line 14: Hardcoded password
```python
f.write('password = "mySuperSecretPassword123!"\n')
```
> 💡 **Fix:** Move to environment variable or secrets manager

#### 🔴 Line 22: Hardcoded secret/token
```python
f.write('SECRET = "a_super_secret_token_of_at_least_16_chars"\n')
```
> 💡 **Fix:** Move to environment variable or secrets manager

#### 🔴 Line 30: OpenAI API key
```python
f.write('openai.api_key = "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\n')
```
> 💡 **Fix:** Move to environment variable or secrets manager

#### 🔴 Line 38: GitHub Personal Access Token
```python
f.write('token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\n')
```
> 💡 **Fix:** Move to environment variable or secrets manager

#### 🔴 Line 46: Slack Bot Token
```python
f.write('SLACK_TOKEN = "xoxb-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\n')
```
> 💡 **Fix:** Move to environment variable or secrets manager

#### 🔴 Line 54: AWS Secret Access Key
```python
f.write('aws_secret_access_key="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\n')
```
> 💡 **Fix:** Move to environment variable or secrets manager

#### 🟡 Line 62: High entropy string detected (entropy=5.25)
```python
f.write('random_string = "AbcDefGhiJklMnoPqrStuVwxYz1234567890+/"\n')
```
> 💡 **Fix:** Review if this is a credential, move to env var if so

#### 🔴 Line 70: Hardcoded API key
```python
f.write('# API_KEY = "a_very_long_and_secretive_api_key_string"\n')
```
> 💡 **Fix:** Move to environment variable or secrets manager

#### 🔴 Line 96: Hardcoded password
```python
f.write('password = "mySuperSecretPassword123!"\n')
```
> 💡 **Fix:** Move to environment variable or secrets manager

---

### 📄 `tests\test_ignore_advanced.py`

#### 🔴 Line 11: OpenAI API key
```python
content = 'key = "sk-12345678901234567890123456789012" # vibe-ignore: rce_risk\neval(input()) # vibe
```
> 💡 **Fix:** Move to environment variable or secrets manager

---

### 📄 `tests\test_quality.py`

#### 🔵 Line 31: Hardcoded localhost URL - use config/env var
```python
f.write('url = "http://localhost:8000"\n')
```
> 💡 **Fix:** Use environment variable: os.getenv('API_URL', 'http://localhost:8000')

#### 🔵 Line 39: Hardcoded localhost URL - use config/env var
```python
f.write('url = "http://127.0.0.1:8000"\n')
```
> 💡 **Fix:** Use environment variable: os.getenv('API_URL', 'http://localhost:8000')

---

### 📄 `tests\test_rce.py`

#### 🔴 Line 6: eval() usage - remote code execution risk
```python
f.write('result = eval(user_input)\n')
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🔴 Line 10: eval() usage - remote code execution risk
```python
assert any(f.rule_id == 'rce_risk' and f.description == 'eval() usage - remote code execution risk' 
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🔴 Line 14: exec() usage - code execution risk
```python
f.write('exec(user_input)\n')
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🔴 Line 18: exec() usage - code execution risk
```python
assert any(f.rule_id == 'rce_risk' and f.description == 'exec() usage - code execution risk' for f i
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🔴 Line 22: os.system() - shell injection risk
```python
f.write('import os\nos.system("ls")\n')
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🔴 Line 26: os.system() - shell injection risk
```python
assert any(f.rule_id == 'rce_risk' and f.description == 'os.system() - shell injection risk' for f i
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🔴 Line 30: subprocess with shell=True - injection risk
```python
f.write('import subprocess\nsubprocess.run("ls", shell=True)\n')
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🟡 Line 38: Dynamic import - potential code injection
```python
f.write('module = __import__("os")\n')
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🟡 Line 46: pickle.load() - arbitrary code execution risk
```python
f.write('import pickle\npickle.load(f)\n')
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🟡 Line 50: pickle.load() - arbitrary code execution risk
```python
assert any(f.rule_id == 'rce_risk' and f.description == 'pickle.load() - arbitrary code execution ri
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🟡 Line 54: yaml.load() without Loader - use yaml.safe_load()
```python
f.write('import yaml\nyaml.load(stream)\n')
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🟡 Line 58: yaml.load() without Loader - use yaml.safe_load()
```python
assert any(f.rule_id == 'rce_risk' and f.description == 'yaml.load() without Loader - use yaml.safe_
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🔴 Line 62: eval() usage - remote code execution risk
```python
f.write('# eval() is dangerous\n')
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

---

### 📄 `tests\test_sqli.py`

#### 🔴 Line 6: SQL string concatenation - injection risk
```python
f.write('query = "SELECT * FROM users WHERE name = \'" + user_input + "\'"\n')
```
> 💡 **Fix:** Use parameterized queries: cursor.execute('SELECT ? FROM ?', (val,))

#### 🔴 Line 14: SQL execute with string concatenation
```python
f.write('cursor.execute("SELECT * FROM users WHERE name = \'" + user_input)\n')
```
> 💡 **Fix:** Use parameterized queries: cursor.execute('SELECT ? FROM ?', (val,))

#### 🔴 Line 22: SQL execute with f-string - injection risk
```python
f.write('cursor.execute(f"SELECT * FROM users WHERE name = \'{user_input}\'")\n')
```
> 💡 **Fix:** Use parameterized queries: cursor.execute('SELECT ? FROM ?', (val,))

#### 🟡 Line 30: SQL with % formatting - use parameterized queries
```python
f.write('query = "SELECT * FROM users WHERE name = %s" % user_input\n')
```
> 💡 **Fix:** Use parameterized queries: cursor.execute('SELECT ? FROM ?', (val,))

#### 🔴 Line 46: SQL string concatenation - injection risk
```python
f.write('# query = "SELECT * FROM users WHERE name = \'" + user_input + "\'"\n')
```
> 💡 **Fix:** Use parameterized queries: cursor.execute('SELECT ? FROM ?', (val,))

#### 🔴 Line 54: SQL string concatenation - injection risk
```python
f.write('x = "this is not a sql query SELECT * from table + name"\n')
```
> 💡 **Fix:** Use parameterized queries: cursor.execute('SELECT ? FROM ?', (val,))

#### 🔴 Line 65: SQL string concatenation - injection risk
```python
f.write('query = "CREATE TABLE " + table_name\n')
```
> 💡 **Fix:** Use parameterized queries: cursor.execute('SELECT ? FROM ?', (val,))

---

### 📄 `venv\Lib\site-packages\_pytest\_code\code.py`

#### 🔴 Line 161: eval() usage - remote code execution risk
```python
def eval(self, code, **vars):
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🔴 Line 170: eval() usage - remote code execution risk
```python
return eval(code, self.f_globals, f_locals)
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🟡 Line 328: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 1494: Silent exception - errors are swallowed silently
```python
except TypeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 1502: Silent exception - errors are swallowed silently
```python
except OSError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\_pytest\_code\source.py`

#### 🟡 Line 140: Silent exception - errors are swallowed silently
```python
except AttributeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 215: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\_pytest\_io\terminalwriter.py`

#### 🟡 Line 81: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\_pytest\_py\path.py`

#### 🟡 Line 83: Silent exception - errors are swallowed silently
```python
except AttributeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 477: Silent exception - errors are swallowed silently
```python
except AttributeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 626: Dynamic import - potential code injection
```python
mod = __import__(hashtype)
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🟡 Line 665: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 975: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 1118: Dynamic import - potential code injection
```python
__import__(modname)
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🔴 Line 1153: exec() usage - code execution risk
```python
exec(f.read(), mod.__dict__)
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🟡 Line 1213: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 1295: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 1404: Silent exception - errors are swallowed silently
```python
except Exception:  # this might be error.Error, WindowsError ...
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 1411: Silent exception - errors are swallowed silently
```python
except Exception:  # this might be error.Error, WindowsError ...
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 1420: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 1427: Silent exception - errors are swallowed silently
```python
except OSError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\_pytest\assertion\rewrite.py`

#### 🔴 Line 197: exec() usage - code execution risk
```python
exec(co, module.__dict__)
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🟡 Line 484: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\_pytest\assertion\util.py`

#### 🟡 Line 153: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\_pytest\capture.py`

#### 🟡 Line 79: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 96: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🔴 Line 1105: os.system() - shell injection risk
```python
os.system('echo "hello"')
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🔴 Line 1133: os.system() - shell injection risk
```python
os.system('echo "hello"')
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

---

### 📄 `venv\Lib\site-packages\_pytest\compat.py`

#### 🟡 Line 81: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 231: Silent exception - errors are swallowed silently
```python
except AttributeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 256: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\_pytest\config\__init__.py`

#### 🟡 Line 462: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 727: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 879: Dynamic import - potential code injection
```python
__import__(importspec)
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🟡 Line 1660: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 2168: Dynamic import - potential code injection
```python
m = __import__(module, None, None, [klass])
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

---

### 📄 `venv\Lib\site-packages\_pytest\config\argparsing.py`

#### 🔴 Line 103: SQL string concatenation - injection risk
```python
self._groups.insert(i + 1, group)
```
> 💡 **Fix:** Use parameterized queries: cursor.execute('SELECT ? FROM ?', (val,))

#### 🔴 Line 106: SQL string concatenation - injection risk
```python
self.optparser._action_groups.insert(i + 1, self.optparser._action_groups.pop())
```
> 💡 **Fix:** Use parameterized queries: cursor.execute('SELECT ? FROM ?', (val,))

#### 🟡 Line 320: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 325: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 348: Silent exception - errors are swallowed silently
```python
except AttributeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\_pytest\debugging.py`

#### 🟡 Line 126: Dynamic import - potential code injection
```python
__import__(modname)
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

---

### 📄 `venv\Lib\site-packages\_pytest\fixtures.py`

#### 🟡 Line 193: Silent exception - errors are swallowed silently
```python
except AttributeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 1867: Silent exception - errors are swallowed silently
```python
except AttributeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 1925: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\_pytest\legacypath.py`

#### 🟡 Line 452: Silent exception - errors are swallowed silently
```python
except AttributeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\_pytest\logging.py`

#### 🟡 Line 195: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 200: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\_pytest\main.py`

#### 🟡 Line 421: Silent exception - errors are swallowed silently
```python
except OSError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\_pytest\mark\__init__.py`

#### 🔴 Line 67: eval() usage - remote code execution risk
```python
assert eval(test_input) == expected
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

---

### 📄 `venv\Lib\site-packages\_pytest\mark\expression.py`

#### 🔴 Line 295: eval() usage - remote code execution risk
```python
"""Adapts a matcher function to a locals mapping as required by eval()."""
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🔴 Line 353: eval() usage - remote code execution risk
```python
return bool(eval(self._code, {"__builtins__": {}}, MatcherAdapter(matcher)))
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

---

### 📄 `venv\Lib\site-packages\_pytest\monkeypatch.py`

#### 🟡 Line 67: Dynamic import - potential code injection
```python
found: object = __import__(used)
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🟡 Line 72: Silent exception - errors are swallowed silently
```python
except AttributeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 79: Dynamic import - potential code injection
```python
__import__(used)
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

---

### 📄 `venv\Lib\site-packages\_pytest\nodes.py`

#### 🟡 Line 453: Silent exception - errors are swallowed silently
```python
except OSError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 588: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 602: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\_pytest\outcomes.py`

#### 🟡 Line 271: Dynamic import - potential code injection
```python
__import__(modname)
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

---

### 📄 `venv\Lib\site-packages\_pytest\pathlib.py`

#### 🟡 Line 201: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 217: Silent exception - errors are swallowed silently
```python
except OSError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 221: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 234: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 276: Silent exception - errors are swallowed silently
```python
except OSError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 306: Silent exception - errors are swallowed silently
```python
except OSError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 542: Silent exception - errors are swallowed silently
```python
except CouldNotResolvePathError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 572: Silent exception - errors are swallowed silently
```python
except CouldNotResolvePathError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 606: Silent exception - errors are swallowed silently
```python
except FileNotFoundError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 1015: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\_pytest\pytester.py`

#### 🔴 Line 295: eval() usage - remote code execution risk
```python
if eval(check, backlocals, call.__dict__):
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🟡 Line 1182: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 1188: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 1473: Silent exception - errors are swallowed silently
```python
except UnicodeEncodeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\_pytest\python_api.py`

#### 🟡 Line 278: Silent exception - errors are swallowed silently
```python
except ZeroDivisionError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 300: Silent exception - errors are swallowed silently
```python
except AttributeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 349: Silent exception - errors are swallowed silently
```python
except TypeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 428: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\_pytest\runner.py`

#### 🟡 Line 176: Silent exception - errors are swallowed silently
```python
except AttributeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\_pytest\skipping.py`

#### 🔴 Line 92: eval() usage - remote code execution risk
```python
If an old-style string condition is given, it is eval()'d, otherwise the
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🔴 Line 119: eval() usage - remote code execution risk
```python
result = eval(condition_code, globals_)
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

---

### 📄 `venv\Lib\site-packages\_pytest\stash.py`

#### 🟡 Line 91: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\_pytest\terminal.py`

#### 🟡 Line 1056: Silent exception - errors are swallowed silently
```python
except AttributeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 1539: Silent exception - errors are swallowed silently
```python
except AttributeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\_pytest\threadexception.py`

#### 🟡 Line 47: Silent exception - errors are swallowed silently
```python
except IndexError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\_pytest\tracemalloc.py`

#### 🟡 Line 10: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\_pytest\unittest.py`

#### 🟡 Line 284: Silent exception - errors are swallowed silently
```python
except TypeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 490: Silent exception - errors are swallowed silently
```python
except AttributeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 580: Silent exception - errors are swallowed silently
```python
except TypeError:  # pragma: no cover
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\_pytest\unraisableexception.py`

#### 🟡 Line 56: Silent exception - errors are swallowed silently
```python
except IndexError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\click\_compat.py`

#### 🟡 Line 44: Silent exception - errors are swallowed silently
```python
except LookupError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 74: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 167: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 418: Silent exception - errors are swallowed silently
```python
except OSError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 528: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 552: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 575: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 600: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\click\_termui_impl.py`

#### 🟡 Line 469: Silent exception - errors are swallowed silently
```python
except BrokenPipeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 485: Silent exception - errors are swallowed silently
```python
except BrokenPipeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 544: Silent exception - errors are swallowed silently
```python
except OSError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\click\_winconsole.py`

#### 🟡 Line 76: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 208: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\click\core.py`

#### 🟡 Line 135: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\click\decorators.py`

#### 🟡 Line 226: Silent exception - errors are swallowed silently
```python
except AttributeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\click\parser.py`

#### 🟡 Line 74: Silent exception - errors are swallowed silently
```python
except IndexError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\click\shell_completion.py`

#### 🟡 Line 354: Silent exception - errors are swallowed silently
```python
except IndexError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 376: Silent exception - errors are swallowed silently
```python
except IndexError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\click\termui.py`

#### 🟡 Line 616: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 622: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\click\testing.py`

#### 🟡 Line 409: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 419: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 500: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 576: Silent exception - errors are swallowed silently
```python
except OSError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\click\types.py`

#### 🟡 Line 189: Silent exception - errors are swallowed silently
```python
except UnicodeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 442: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 1165: Silent exception - errors are swallowed silently
```python
except TypeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\click\utils.py`

#### 🟡 Line 42: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\colorama\initialise.py`

#### 🟡 Line 27: Silent exception - errors are swallowed silently
```python
except AttributeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\colorama\tests\ansitowin32_test.py`

#### 🟡 Line 12: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\colorama\tests\initialise_test.py`

#### 🟡 Line 7: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\colorama\tests\winterm_test.py`

#### 🟡 Line 7: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\iniconfig\_parse.py`

#### 🟡 Line 137: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\markdown_it\common\utils.py`

#### 🟡 Line 24: Silent exception - errors are swallowed silently
```python
except IndexError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 39: Silent exception - errors are swallowed silently
```python
except IndexError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\markdown_it\main.py`

#### 🟡 Line 19: Silent exception - errors are swallowed silently
```python
except ModuleNotFoundError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\markdown_it\rules_block\blockquote.py`

#### 🟡 Line 42: Silent exception - errors are swallowed silently
```python
except IndexError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 160: Silent exception - errors are swallowed silently
```python
except IndexError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\markdown_it\rules_block\fence.py`

#### 🟡 Line 68: Silent exception - errors are swallowed silently
```python
except IndexError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\markdown_it\rules_block\heading.py`

#### 🟡 Line 39: Silent exception - errors are swallowed silently
```python
except IndexError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\markdown_it\rules_block\state_block.py`

#### 🟡 Line 143: Silent exception - errors are swallowed silently
```python
except IndexError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\markdown_it\rules_inline\strikethrough.py`

#### 🟡 Line 122: Silent exception - errors are swallowed silently
```python
except IndexError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\mdurl\_decode.py`

#### 🟡 Line 61: Silent exception - errors are swallowed silently
```python
except UnicodeDecodeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 77: Silent exception - errors are swallowed silently
```python
except UnicodeDecodeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 94: Silent exception - errors are swallowed silently
```python
except UnicodeDecodeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\packaging\_manylinux.py`

#### 🟡 Line 111: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 129: Silent exception - errors are swallowed silently
```python
except OSError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\packaging\metadata.py`

#### 🟡 Line 567: Silent exception - errors are swallowed silently
```python
except AttributeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 575: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\packaging\tags.py`

#### 🟡 Line 226: Silent exception - errors are swallowed silently
```python
except ValueError:  # noqa: PERF203
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_internal\cli\autocompletion.py`

#### 🟡 Line 30: Silent exception - errors are swallowed silently
```python
except IndexError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_internal\cli\cmdoptions.py`

#### 🟡 Line 622: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_internal\commands\configuration.py`

#### 🔴 Line 247: subprocess with shell=True - injection risk
```python
subprocess.check_call(f'{editor} "{fname}"', shell=True)
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

---

### 📄 `venv\Lib\site-packages\pip\_internal\commands\debug.py`

#### 🟡 Line 59: Dynamic import - potential code injection
```python
__import__(f"pip._vendor.{module_name}", globals(), locals(), level=0)
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

---

### 📄 `venv\Lib\site-packages\pip\_internal\commands\help.py`

#### 🟡 Line 25: Silent exception - errors are swallowed silently
```python
except IndexError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_internal\commands\search.py`

#### 🟡 Line 173: Silent exception - errors are swallowed silently
```python
except UnicodeEncodeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_internal\commands\show.py`

#### 🟡 Line 113: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 133: Silent exception - errors are swallowed silently
```python
except FileNotFoundError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_internal\configuration.py`

#### 🟡 Line 136: Silent exception - errors are swallowed silently
```python
except IndexError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 211: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_internal\exceptions.py`

#### 🟡 Line 751: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_internal\index\package_finder.py`

#### 🟡 Line 871: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_internal\locations\_distutils.py`

#### 🟡 Line 15: Dynamic import - potential code injection
```python
__import__("_distutils_hack").remove_shim()
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

---

### 📄 `venv\Lib\site-packages\pip\_internal\locations\base.py`

#### 🟡 Line 76: Silent exception - errors are swallowed silently
```python
except AttributeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_internal\metadata\importlib\_dists.py`

#### 🟡 Line 175: Silent exception - errors are swallowed silently
```python
except TypeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_internal\metadata\pkg_resources.py`

#### 🟡 Line 180: Silent exception - errors are swallowed silently
```python
except AttributeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_internal\network\auth.py`

#### 🟡 Line 174: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 209: Silent exception - errors are swallowed silently
```python
except FileNotFoundError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_internal\network\cache.py`

#### 🟡 Line 35: Silent exception - errors are swallowed silently
```python
except OSError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_internal\network\session.py`

#### 🟡 Line 185: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🔴 Line 311: SSL certificate verification disabled (verify=False)
```python
super().cert_verify(conn=conn, url=url, verify=False, cert=cert)
```
> 💡 **Fix:** Fix the insecure shortcut (e.g. restrict CORS, remove verify=False, don't log process.env)

#### 🔴 Line 322: SSL certificate verification disabled (verify=False)
```python
super().cert_verify(conn=conn, url=url, verify=False, cert=cert)
```
> 💡 **Fix:** Fix the insecure shortcut (e.g. restrict CORS, remove verify=False, don't log process.env)

---

### 📄 `venv\Lib\site-packages\pip\_internal\operations\build\build_tracker.py`

#### 🟡 Line 100: Silent exception - errors are swallowed silently
```python
except FileNotFoundError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_internal\operations\prepare.py`

#### 🟡 Line 100: Silent exception - errors are swallowed silently
```python
except OSError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_internal\req\constructors.py`

#### 🟡 Line 148: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_internal\req\req_uninstall.py`

#### 🟡 Line 232: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 627: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_internal\resolution\legacy\resolver.py`

#### 🟡 Line 251: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_internal\resolution\resolvelib\factory.py`

#### 🟡 Line 278: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_internal\self_outdated_check.py`

#### 🟡 Line 136: Silent exception - errors are swallowed silently
```python
except OSError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_internal\utils\compat.py`

#### 🟡 Line 21: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_internal\utils\filesystem.py`

#### 🟡 Line 97: High entropy string detected (entropy=5.17)
```python
alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
```
> 💡 **Fix:** Review if this is a credential, move to env var if so

#### 🟡 Line 103: Silent exception - errors are swallowed silently
```python
except FileExistsError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_internal\utils\glibc.py`

#### 🟡 Line 37: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 55: Silent exception - errors are swallowed silently
```python
except OSError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_internal\utils\logging.py`

#### 🟡 Line 199: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_internal\utils\misc.py`

#### 🟡 Line 167: Silent exception - errors are swallowed silently
```python
except OSError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 174: Silent exception - errors are swallowed silently
```python
except OSError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 348: Silent exception - errors are swallowed silently
```python
except OSError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_internal\utils\unpacking.py`

#### 🟡 Line 33: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 41: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 261: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_internal\utils\virtualenv.py`

#### 🟡 Line 48: Silent exception - errors are swallowed silently
```python
except OSError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_internal\utils\wheel.py`

#### 🟡 Line 107: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_internal\vcs\git.py`

#### 🟡 Line 408: Silent exception - errors are swallowed silently
```python
except IndexError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_internal\vcs\subversion.py`

#### 🟡 Line 171: Silent exception - errors are swallowed silently
```python
except InstallationError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 223: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\__init__.py`

#### 🟡 Line 33: Dynamic import - potential code injection
```python
__import__(modulename, globals(), locals(), level=0)
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

---

### 📄 `venv\Lib\site-packages\pip\_vendor\cachecontrol\caches\file_cache.py`

#### 🟡 Line 71: Silent exception - errors are swallowed silently
```python
except FileNotFoundError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 103: Silent exception - errors are swallowed silently
```python
except FileNotFoundError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 127: Silent exception - errors are swallowed silently
```python
except FileNotFoundError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\cachecontrol\filewrapper.py`

#### 🟡 Line 56: Silent exception - errors are swallowed silently
```python
except AttributeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 63: Silent exception - errors are swallowed silently
```python
except AttributeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\cachecontrol\serialize.py`

#### 🟡 Line 143: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\dependency_groups\_toml_compat.py`

#### 🟡 Line 6: Silent exception - errors are swallowed silently
```python
except ModuleNotFoundError:  # pragma: no cover
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\distlib\__init__.py`

#### 🟡 Line 18: Silent exception - errors are swallowed silently
```python
except ImportError:  # pragma: no cover
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\distlib\compat.py`

#### 🟡 Line 16: Silent exception - errors are swallowed silently
```python
except ImportError:  # pragma: no cover
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 91: Silent exception - errors are swallowed silently
```python
except ImportError:  # pragma: no cover
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 190: Silent exception - errors are swallowed silently
```python
except ImportError:  # pragma: no cover
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 305: Silent exception - errors are swallowed silently
```python
except ImportError:  # pragma: no cover
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 322: Silent exception - errors are swallowed silently
```python
except NameError:  # pragma: no cover
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 366: Silent exception - errors are swallowed silently
```python
except ImportError:  # pragma: no cover
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 487: Silent exception - errors are swallowed silently
```python
except ImportError:  # pragma: no cover
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 492: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 552: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 612: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 630: Silent exception - errors are swallowed silently
```python
except ImportError:  # pragma: no cover
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 651: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 656: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 732: Silent exception - errors are swallowed silently
```python
except AttributeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 912: Silent exception - errors are swallowed silently
```python
except ImportError:  # pragma: no cover
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\distlib\resources.py`

#### 🟡 Line 323: Dynamic import - potential code injection
```python
__import__(package)
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

---

### 📄 `venv\Lib\site-packages\pip\_vendor\distlib\util.py`

#### 🟡 Line 365: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 676: Dynamic import - potential code injection
```python
mod = __import__(module_name)
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🟡 Line 1121: Silent exception - errors are swallowed silently
```python
except KeyError:  # pragma: no cover
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🔴 Line 1336: SQL string concatenation - injection risk
```python
self.update(self.cur + incr)
```
> 💡 **Fix:** Use parameterized queries: cursor.execute('SELECT ? FROM ?', (val,))

---

### 📄 `venv\Lib\site-packages\pip\_vendor\distro\distro.py`

#### 🟡 Line 1225: Silent exception - errors are swallowed silently
```python
except FileNotFoundError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\idna\core.py`

#### 🟡 Line 291: Silent exception - errors are swallowed silently
```python
except UnicodeEncodeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\msgpack\__init__.py`

#### 🟡 Line 16: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\msgpack\fallback.py`

#### 🟡 Line 573: Silent exception - errors are swallowed silently
```python
except RecursionError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\packaging\_manylinux.py`

#### 🟡 Line 110: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 128: Silent exception - errors are swallowed silently
```python
except OSError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\packaging\licenses\__init__.py`

#### 🔴 Line 100: eval() usage - remote code execution risk
```python
invalid = eval(python_expression, globals(), locals())
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🟡 Line 101: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\packaging\metadata.py`

#### 🟡 Line 511: Silent exception - errors are swallowed silently
```python
except AttributeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 519: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\packaging\tags.py`

#### 🟡 Line 221: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\pkg_resources\__init__.py`

#### 🟡 Line 217: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 427: Dynamic import - potential code injection
```python
__import__(moduleOrReq)
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🟡 Line 1432: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🔴 Line 1714: exec() usage - code execution risk
```python
exec(code, namespace, namespace)
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🔴 Line 1725: exec() usage - code execution risk
```python
exec(script_code, namespace, namespace)
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🟡 Line 2486: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 2530: Dynamic import - potential code injection
```python
__import__(parent)
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🟡 Line 2751: Dynamic import - potential code injection
```python
module = __import__(self.module_name, fromlist=['__name__'], level=0)
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🟡 Line 3094: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 3413: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 3516: Silent exception - errors are swallowed silently
```python
except FileExistsError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\platformdirs\android.py`

#### 🟡 Line 177: Silent exception - errors are swallowed silently
```python
except Exception:  # noqa: BLE001
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 193: Silent exception - errors are swallowed silently
```python
except Exception:  # noqa: BLE001
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 209: Silent exception - errors are swallowed silently
```python
except Exception:  # noqa: BLE001
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 225: Silent exception - errors are swallowed silently
```python
except Exception:  # noqa: BLE001
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 241: Silent exception - errors are swallowed silently
```python
except Exception:  # noqa: BLE001
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\platformdirs\windows.py`

#### 🟡 Line 255: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\pygments\filters\__init__.py`

#### 🟡 Line 779: Silent exception - errors are swallowed silently
```python
except TypeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\pygments\formatters\__init__.py`

#### 🟡 Line 38: Dynamic import - potential code injection
```python
mod = __import__(module_name, None, None, ['__all__'])
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🔴 Line 91: eval() usage - remote code execution risk
```python
this method is equivalent to running ``eval()`` on the input file. The formatter is
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🔴 Line 103: exec() usage - code execution risk
```python
exec(f.read(), custom_namespace)
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

---

### 📄 `venv\Lib\site-packages\pip\_vendor\pygments\lexer.py`

#### 🟡 Line 646: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 760: Silent exception - errors are swallowed silently
```python
except IndexError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 847: Silent exception - errors are swallowed silently
```python
except IndexError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\pygments\lexers\__init__.py`

#### 🟡 Line 45: Dynamic import - potential code injection
```python
mod = __import__(module_name, None, None, ['__all__'])
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🔴 Line 154: exec() usage - code execution risk
```python
exec(f.read(), custom_namespace)
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

---

### 📄 `venv\Lib\site-packages\pip\_vendor\pygments\sphinxext.py`

#### 🟡 Line 161: Dynamic import - potential code injection
```python
mod = __import__(module, None, None, [classname])
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🟡 Line 221: Dynamic import - potential code injection
```python
mod = __import__(module, None, None, [classname])
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

---

### 📄 `venv\Lib\site-packages\pip\_vendor\pygments\styles\__init__.py`

#### 🟡 Line 45: Dynamic import - potential code injection
```python
mod = __import__(mod, None, None, [cls])
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🟡 Line 52: Silent exception - errors are swallowed silently
```python
except AttributeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\pygments\util.py`

#### 🟡 Line 306: Silent exception - errors are swallowed silently
```python
except UnicodeDecodeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\requests\__init__.py`

#### 🟡 Line 87: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 122: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 134: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\requests\adapters.py`

#### 🟡 Line 60: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\requests\cookies.py`

#### 🟡 Line 19: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 203: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 324: Silent exception - errors are swallowed silently
```python
except CookieConflictError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\requests\models.py`

#### 🟡 Line 226: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\requests\packages.py`

#### 🟡 Line 10: Dynamic import - potential code injection
```python
locals()[package] = __import__(vendored_package)
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

---

### 📄 `venv\Lib\site-packages\pip\_vendor\requests\sessions.py`

#### 🟡 Line 323: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\requests\utils.py`

#### 🟡 Line 80: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 198: Silent exception - errors are swallowed silently
```python
except OSError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 610: Silent exception - errors are swallowed silently
```python
except UnicodeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 616: Silent exception - errors are swallowed silently
```python
except TypeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 622: High entropy string detected (entropy=5.70)
```python
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" + "0123456789-._~"
```
> 💡 **Fix:** Review if this is a credential, move to env var if so

#### 🟡 Line 638: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 718: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 923: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 931: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\rich\_emoji_replace.py`

#### 🟡 Line 29: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\rich\_inspect.py`

#### 🟡 Line 88: Silent exception - errors are swallowed silently
```python
except TypeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\rich\_wrap.py`

#### 🟡 Line 86: High entropy string detected (entropy=4.70)
```python
print(chop_cells("abcdefghijklmnopqrstuvwxyz", 10))
```
> 💡 **Fix:** Review if this is a credential, move to env var if so

---

### 📄 `venv\Lib\site-packages\pip\_vendor\rich\console.py`

#### 🟡 Line 95: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 2039: Silent exception - errors are swallowed silently
```python
except BrokenPipeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\rich\live.py`

#### 🟡 Line 253: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\rich\logging.py`

#### 🟡 Line 179: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 290: Silent exception - errors are swallowed silently
```python
except:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\rich\pager.py`

#### 🟡 Line 21: Dynamic import - potential code injection
```python
return __import__("pydoc").pager(content)
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

---

### 📄 `venv\Lib\site-packages\pip\_vendor\rich\pretty.py`

#### 🟡 Line 36: Silent exception - errors are swallowed silently
```python
except ImportError:  # pragma: no cover
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 86: Silent exception - errors are swallowed silently
```python
except Exception:  # pragma: no coverage
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 167: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 653: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 661: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\rich\progress.py`

#### 🟡 Line 534: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\rich\prompt.py`

#### 🟡 Line 242: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\rich\text.py`

#### 🟡 Line 1282: Silent exception - errors are swallowed silently
```python
except TypeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\rich\traceback.py`

#### 🟡 Line 458: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\tomli\_parser.py`

#### 🟡 Line 52: High entropy string detected (entropy=4.70)
```python
"abcdefghijklmnopqrstuvwxyz" "ABCDEFGHIJKLMNOPQRSTUVWXYZ" "0123456789" "-_"
```
> 💡 **Fix:** Review if this is a credential, move to env var if so

#### 🟡 Line 52: High entropy string detected (entropy=4.70)
```python
"abcdefghijklmnopqrstuvwxyz" "ABCDEFGHIJKLMNOPQRSTUVWXYZ" "0123456789" "-_"
```
> 💡 **Fix:** Review if this is a credential, move to env var if so

#### 🟡 Line 321: Silent exception - errors are swallowed silently
```python
except IndexError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 379: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 402: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 586: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 692: Silent exception - errors are swallowed silently
```python
except IndexError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\tomli_w\_writer.py`

#### 🟡 Line 16: High entropy string detected (entropy=4.70)
```python
"abcdefghijklmnopqrstuvwxyz" "ABCDEFGHIJKLMNOPQRSTUVWXYZ" "0123456789" "-_"
```
> 💡 **Fix:** Review if this is a credential, move to env var if so

#### 🟡 Line 16: High entropy string detected (entropy=4.70)
```python
"abcdefghijklmnopqrstuvwxyz" "ABCDEFGHIJKLMNOPQRSTUVWXYZ" "0123456789" "-_"
```
> 💡 **Fix:** Review if this is a credential, move to env var if so

---

### 📄 `venv\Lib\site-packages\pip\_vendor\truststore\_api.py`

#### 🟡 Line 45: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 62: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 73: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 335: Silent exception - errors are swallowed silently
```python
except AttributeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\truststore\_macos.py`

#### 🟡 Line 44: Silent exception - errors are swallowed silently
```python
except OSError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\urllib3\__init__.py`

#### 🟡 Line 28: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\urllib3\_collections.py`

#### 🟡 Line 9: Silent exception - errors are swallowed silently
```python
except ImportError:  # Platform-specific: No threads available
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 212: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\urllib3\connection.py`

#### 🟡 Line 40: Silent exception - errors are swallowed silently
```python
except NameError:  # Python 2:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\urllib3\connectionpool.py`

#### 🟡 Line 58: Silent exception - errors are swallowed silently
```python
except AttributeError:  # Platform-specific: Python 2
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 278: Silent exception - errors are swallowed silently
```python
except AttributeError:  # self.pool is None
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 318: Silent exception - errors are swallowed silently
```python
except AttributeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 421: Silent exception - errors are swallowed silently
```python
except BrokenPipeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\urllib3\contrib\_securetransport\bindings.py`

#### 🟡 Line 77: Silent exception - errors are swallowed silently
```python
except OSError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 301: Silent exception - errors are swallowed silently
```python
except AttributeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\urllib3\contrib\appengine.py`

#### 🟡 Line 64: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\urllib3\contrib\pyopenssl.py`

#### 🟡 Line 33: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\urllib3\contrib\securetransport.py`

#### 🔴 Line 794: SSL certificate verification disabled (verify=False)
```python
self._verify = False
```
> 💡 **Fix:** Fix the insecure shortcut (e.g. restrict CORS, remove verify=False, don't log process.env)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\urllib3\contrib\socks.py`

#### 🟡 Line 45: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 71: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\urllib3\packages\six.py`

#### 🟡 Line 87: Dynamic import - potential code injection
```python
__import__(name)
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🟡 Line 102: Silent exception - errors are swallowed silently
```python
except AttributeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 198: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 205: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 556: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 580: Silent exception - errors are swallowed silently
```python
except NameError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 591: Silent exception - errors are swallowed silently
```python
except NameError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🔴 Line 787: exec() usage - code execution risk
```python
exec ("""exec _code_ in _globs_, _locs_""")
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

---

### 📄 `venv\Lib\site-packages\pip\_vendor\urllib3\poolmanager.py`

#### 🟡 Line 317: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🔵 Line 452: Hardcoded localhost URL - use config/env var
```python
>>> proxy = urllib3.ProxyManager('http://localhost:3128/')
```
> 💡 **Fix:** Use environment variable: os.getenv('API_URL', 'http://localhost:8000')

---

### 📄 `venv\Lib\site-packages\pip\_vendor\urllib3\response.py`

#### 🟡 Line 360: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\urllib3\util\connection.py`

#### 🟡 Line 29: Silent exception - errors are swallowed silently
```python
except NoWayToWaitForSocketError:  # Platform-specific: AppEngine
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 141: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\urllib3\util\response.py`

#### 🟡 Line 21: Silent exception - errors are swallowed silently
```python
except AttributeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 27: Silent exception - errors are swallowed silently
```python
except AttributeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 34: Silent exception - errors are swallowed silently
```python
except AttributeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\urllib3\util\retry.py`

#### 🟡 Line 617: Silent exception - errors are swallowed silently
```python
except AttributeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\urllib3\util\ssl_.py`

#### 🟡 Line 51: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 56: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 61: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 74: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 79: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 92: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 134: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 434: Silent exception - errors are swallowed silently
```python
except NotImplementedError:  # Defensive: in CI, we always have set_alpn_protocols
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\urllib3\util\ssl_match_hostname.py`

#### 🟡 Line 15: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pip\_vendor\urllib3\util\wait.py`

#### 🟡 Line 8: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pluggy\_hooks.py`

#### 🟡 Line 308: Silent exception - errors are swallowed silently
```python
except Exception:  # pragma: no cover - pypy special case
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 316: Silent exception - errors are swallowed silently
```python
except TypeError:  # pragma: no cover
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🔴 Line 473: SQL string concatenation - injection risk
```python
self._hookimpls.insert(i + 1, hookimpl)
```
> 💡 **Fix:** Use parameterized queries: cursor.execute('SELECT ? FROM ?', (val,))

#### 🔴 Line 571: SQL string concatenation - injection risk
```python
hookimpls.insert(i + 1, hookimpl)
```
> 💡 **Fix:** Use parameterized queries: cursor.execute('SELECT ? FROM ?', (val,))

---

### 📄 `venv\Lib\site-packages\pluggy\_tracing.py`

#### 🟡 Line 47: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pygments\cmdline.py`

#### 🔵 Line 1: Excessive print() usage: 53 calls - use logging
```python

```
> 💡 **Fix:** Replace print() with logging module

#### 🟡 Line 473: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 522: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pygments\filters\__init__.py`

#### 🟡 Line 779: Silent exception - errors are swallowed silently
```python
except TypeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pygments\formatters\__init__.py`

#### 🟡 Line 38: Dynamic import - potential code injection
```python
mod = __import__(module_name, None, None, ['__all__'])
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🔴 Line 91: eval() usage - remote code execution risk
```python
this method is equivalent to running ``eval()`` on the input file. The formatter is
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🔴 Line 103: exec() usage - code execution risk
```python
exec(f.read(), custom_namespace)
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

---

### 📄 `venv\Lib\site-packages\pygments\formatters\html.py`

#### 🟡 Line 23: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 463: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pygments\formatters\img.py`

#### 🟡 Line 23: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 31: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 198: Silent exception - errors are swallowed silently
```python
except OSError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 262: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 264: Silent exception - errors are swallowed silently
```python
except OSError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 440: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pygments\formatters\other.py`

#### 🟡 Line 76: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pygments\formatters\rtf.py`

#### 🟡 Line 139: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pygments\formatters\terminal256.py`

#### 🟡 Line 214: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pygments\lexer.py`

#### 🟡 Line 644: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 758: Silent exception - errors are swallowed silently
```python
except IndexError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 845: Silent exception - errors are swallowed silently
```python
except IndexError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pygments\lexers\__init__.py`

#### 🟡 Line 45: Dynamic import - potential code injection
```python
mod = __import__(module_name, None, None, ['__all__'])
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🔴 Line 154: exec() usage - code execution risk
```python
exec(f.read(), custom_namespace)
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

---

### 📄 `venv\Lib\site-packages\pygments\lexers\_julia_builtins.py`

#### 🔴 Line 150: eval() usage - remote code execution risk
```python
v = eval(Symbol(compl.mod))
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🔴 Line 361: eval() usage - remote code execution risk
```python
v = eval(Symbol(compl.mod))
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

---

### 📄 `venv\Lib\site-packages\pygments\lexers\business.py`

#### 🔴 Line 338: SQL string concatenation - injection risk
```python
r'AT\s+(LINE-SELECTION|USER-COMMAND|END\s+OF|NEW)|'
```
> 💡 **Fix:** Use parameterized queries: cursor.execute('SELECT ? FROM ?', (val,))

#### 🔴 Line 339: SQL string concatenation - injection risk
```python
r'AT\s+SELECTION-SCREEN(\s+(ON(\s+(BLOCK|(HELP|VALUE)-REQUEST\s+FOR|'
```
> 💡 **Fix:** Use parameterized queries: cursor.execute('SELECT ? FROM ?', (val,))

#### 🔴 Line 341: SQL string concatenation - injection risk
```python
r'SELECTION-SCREEN:?\s+((BEGIN|END)\s+OF\s+((TABBED\s+)?BLOCK|LINE|'
```
> 💡 **Fix:** Use parameterized queries: cursor.execute('SELECT ? FROM ?', (val,))

#### 🔴 Line 352: SQL string concatenation - injection risk
```python
r'DELETE(\s+ADJACENT\s+DUPLICATES\sFROM)?|'
```
> 💡 **Fix:** Use parameterized queries: cursor.execute('SELECT ? FROM ?', (val,))

#### 🔴 Line 354: SQL string concatenation - injection risk
```python
r'(INSERT|APPEND)(\s+INITIAL\s+LINE\s+(IN)?TO|\s+LINES\s+OF)?|'
```
> 💡 **Fix:** Use parameterized queries: cursor.execute('SELECT ? FROM ?', (val,))

#### 🔴 Line 361: SQL string concatenation - injection risk
```python
r'IN\s+UPDATE\s+TASK|'
```
> 💡 **Fix:** Use parameterized queries: cursor.execute('SELECT ? FROM ?', (val,))

---

### 📄 `venv\Lib\site-packages\pygments\lexers\rdf.py`

#### 🔴 Line 99: SQL string concatenation - injection risk
```python
(r'(?i)(select|construct|describe|ask|where|filter|group\s+by|minus|'
```
> 💡 **Fix:** Use parameterized queries: cursor.execute('SELECT ? FROM ?', (val,))

#### 🔴 Line 102: SQL string concatenation - injection risk
```python
r'insert\s+data|delete\s+data|delete\s+where|with|delete|insert|'
```
> 💡 **Fix:** Use parameterized queries: cursor.execute('SELECT ? FROM ?', (val,))

---

### 📄 `venv\Lib\site-packages\pygments\lexers\robotframework.py`

#### 🟡 Line 445: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pygments\lexers\templates.py`

#### 🟡 Line 139: Silent exception - errors are swallowed silently
```python
except IndexError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pygments\sphinxext.py`

#### 🟡 Line 161: Dynamic import - potential code injection
```python
mod = __import__(module, None, None, [classname])
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🟡 Line 221: Dynamic import - potential code injection
```python
mod = __import__(module, None, None, [classname])
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

---

### 📄 `venv\Lib\site-packages\pygments\styles\__init__.py`

#### 🟡 Line 45: Dynamic import - potential code injection
```python
mod = __import__(mod, None, None, [cls])
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🟡 Line 52: Silent exception - errors are swallowed silently
```python
except AttributeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\pygments\util.py`

#### 🟡 Line 306: Silent exception - errors are swallowed silently
```python
except UnicodeDecodeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\rich\_emoji_replace.py`

#### 🟡 Line 29: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\rich\_inspect.py`

#### 🟡 Line 88: Silent exception - errors are swallowed silently
```python
except TypeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\rich\_wrap.py`

#### 🟡 Line 86: High entropy string detected (entropy=4.70)
```python
print(chop_cells("abcdefghijklmnopqrstuvwxyz", 10))
```
> 💡 **Fix:** Review if this is a credential, move to env var if so

---

### 📄 `venv\Lib\site-packages\rich\console.py`

#### 🟡 Line 95: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 2043: Silent exception - errors are swallowed silently
```python
except BrokenPipeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\rich\live.py`

#### 🟡 Line 257: Silent exception - errors are swallowed silently
```python
except ImportError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\rich\logging.py`

#### 🟡 Line 179: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 290: Silent exception - errors are swallowed silently
```python
except:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\rich\pager.py`

#### 🟡 Line 21: Dynamic import - potential code injection
```python
return __import__("pydoc").pager(content)
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

---

### 📄 `venv\Lib\site-packages\rich\pretty.py`

#### 🟡 Line 36: Silent exception - errors are swallowed silently
```python
except ImportError:  # pragma: no cover
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 86: Silent exception - errors are swallowed silently
```python
except Exception:  # pragma: no coverage
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 167: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 653: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

#### 🟡 Line 661: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\rich\progress.py`

#### 🟡 Line 534: Silent exception - errors are swallowed silently
```python
except KeyError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\rich\prompt.py`

#### 🟡 Line 242: Silent exception - errors are swallowed silently
```python
except ValueError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\rich\text.py`

#### 🟡 Line 1284: Silent exception - errors are swallowed silently
```python
except TypeError:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `venv\Lib\site-packages\rich\traceback.py`

#### 🟡 Line 480: Silent exception - errors are swallowed silently
```python
except Exception:
```
> 💡 **Fix:** Log the exception: except Exception as e: logger.error(e)

---

### 📄 `vibe_guard\reporter.py`

#### 🔵 Line 13: Hardcoded localhost URL - use config/env var
```python
"hardcoded_localhost": "Use environment variable: os.getenv('API_URL', 'http://localhost:8000')",
```
> 💡 **Fix:** Use environment variable: os.getenv('API_URL', 'http://localhost:8000')

#### 🔴 Line 17: SSL certificate verification disabled (verify=False)
```python
"insecure_default": "Fix the insecure shortcut (e.g. restrict CORS, remove verify=False, don't log p
```
> 💡 **Fix:** Fix the insecure shortcut (e.g. restrict CORS, remove verify=False, don't log process.env)

---

### 📄 `vibe_guard\rules\insecure_defaults.py`

#### 🔴 Line 10: SSL certificate verification disabled (verify=False)
```python
(r'verify\s*=\s*False', "critical", "SSL certificate verification disabled (verify=False)"),
```
> 💡 **Fix:** Fix the insecure shortcut (e.g. restrict CORS, remove verify=False, don't log process.env)

---

### 📄 `vibe_guard\rules\rce.py`

#### 🔴 Line 8: eval() usage - remote code execution risk
```python
(r'\beval\s*\(', "critical", "eval() usage - remote code execution risk"),
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🔴 Line 9: exec() usage - code execution risk
```python
(r'\bexec\s*\(', "critical", "exec() usage - code execution risk"),
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🔴 Line 10: os.system() - shell injection risk
```python
(r'os\.system\s*\(', "critical", "os.system() - shell injection risk"),
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🟡 Line 13: pickle.load() - arbitrary code execution risk
```python
(r'pickle\.loads?\s*\(', "warning", "pickle.load() - arbitrary code execution risk"),
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

#### 🟡 Line 14: yaml.load() without Loader - use yaml.safe_load()
```python
(r'yaml\.load\s*\([^,)]*\)', "warning", "yaml.load() without Loader - use yaml.safe_load()"),
```
> 💡 **Fix:** Use subprocess with shell=False and argument lists instead

---

### 📄 `vibe_guard\rules\supabase.py`

#### 🔴 Line 11: SQL string concatenation - injection risk
```python
(r'(?i)create\s+policy.*using\s*\(\s*true\s*\)', "warning", "Overly permissive Supabase RLS policy (
```
> 💡 **Fix:** Use parameterized queries: cursor.execute('SELECT ? FROM ?', (val,))

#### 🔴 Line 13: SQL string concatenation - injection risk
```python
(r'(?i)create\s+policy.*for\s+(?:insert|update|all)(?:(?!with\s+check).)*;', "warning", "Supabase RL
```
> 💡 **Fix:** Use parameterized queries: cursor.execute('SELECT ? FROM ?', (val,))

---
