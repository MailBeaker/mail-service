Mail Service
============

Horizontally scalable Gmail API message processing in Python.

----------------------------------------------
Requirements
----------------------------------------------

1. sudo apt-get install python-dev python-pip libffi-dev libssl-dev git
2. sudo pip -r requirements.txt

----------------------------------------------
Operation
----------------------------------------------

For basic testing, start the worker:
```
cd /opt/mail-service/mail_service/
celery worker -A mail_service.gmail_service.worker --loglevel=info
```

In another window, add a test task:
```
python add_test_task.py
```

Back in the original window, you should see the worker print out the results of the test task.

----------------------------------------------
Configuration
----------------------------------------------

Production settings are stored in the settings.py file.  For development work, please create a settingslocal.py file, which will be ignored by Git.
