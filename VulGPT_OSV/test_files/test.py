import os
import sqlite3
import pickle
import subprocess
import hashlib
import requests
from flask import Flask, request, render_template_string, redirect

app = Flask(__name__)

# Hardcoded credentials (CWE-798)
DB_USERNAME = "admin"
DB_PASSWORD = "password123"  # Hardcoded password (CWE-798)