from flask import Flask, render_template,abort,jsonify,redirect,url_for,request,Response, stream_with_context,send_file,session
from flask import *
import requests
import sys
import psycopg2
import json
import hashlib
import time
from datetime import timedelta
from datetime import datetime, timezone
from datetime import timezone, datetime
from flask_cors import CORS
import os
import logging
import os.path
#import ctypes
import re
import uuid
import csv
import base64
from mailjet_rest import Client
import secrets
from flask import session, app
# import paho.mqtt.client as paho
# import webview
import webbrowser
from threading import Timer
import openai
from datetime import datetime, timezone
#strr = email_id + str(datetime.now(timezone.utc))
from flask_caching import Cache
import pandas as pd
from collections import defaultdict
import re

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

#cache = Cache(app, config={'CACHE_TYPE': 'simple'})

password_length = 10

api_key = 'ade816fae25d30c7c6f8381f46ee5c88'
api_secret = '40e2bd5b64f7606ba267f3b4bd74047c'
mailjet = Client(auth=(api_key, api_secret), version='v3.1')

pth = os.path.join(os.path.dirname(sys.argv[0]), sys.argv[0]+".log")
logging.basicConfig(filename=pth, level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('main')
logger.info("Server Started")
print("Server Started:  ", file=sys.stderr)

f = open(os.path.join(os.path.dirname("config"), "config"+".json"))

db_cred = json.load(f)



app = Flask(__name__, static_url_path='', static_folder='static', template_folder='static')
# window = webview.create_window('IndustryInCloud',app,frameless=False,confirm_close=True, width=1920, height=1200)
CORS(app, supports_credentials=True)
app.secret_key = "ksdnu32nbasd1mnj43242nnksk32"
# session.permanent = True
# app.permanent_session_lifetime = timedelta(minutes=30)

months = ["Unknown",
          "Jan",
          "Feb",
          "Mar",
          "Apr",
          "May",
          "Jun",
          "Jul",
          "Aug",
          "Sep",
          "Oct",
          "Nov",
          "Dec"]

@app.before_request
def before_request():
    now = datetime.now()
    try:
        last_active = session['expires']
        delta = now - last_active
        if delta.seconds > 1800:
            session['expires'] = now
            flash("Session expired, Please try again...!")
            return redirect(url_for('logout'))
    except:
        pass

    try:
        session['expires'] = now
    except:
        pass


# Database creds
t_host = db_cred['host']
t_port = db_cred['port'] 
t_dbname = db_cred['dbname']
t_user = db_cred['user']
t_pw = db_cred['password']

dbcon = "host='"+t_host+"' dbname ='"+t_dbname+"' user='"+t_user+"' password='"+t_pw+"' port='"+t_port+"'"
regex = r'^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w+$'






regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

                
def getSessionKey(email_id):
    strr = email_id + str(datetime.now(timezone.utc))
    skey=hashlib.sha256(strr.encode('utf-8')).hexdigest()
    return skey

def validSession(db_conn, sessionkey):
    try:
        pno = None

        if not sessionkey:
            print("sessionkey is None or empty")
            return None  # Se il valore non è valido, esci subito
        
        print(f"Validating session with key: '{sessionkey}'")

        db_cursor = db_conn.cursor()
        db_cursor.execute ("""select email_id from user_details where session_id = %s""",(sessionkey,))
        result = db_cursor.fetchone()
        if result and sessionkey:
            print(f"Sessionkey valido, email trovata: {result[0]}")
            pno = sessionkey
        db_cursor.close()
        return pno
    except Exception as e:
        logger.exception(e)
        return render_template("page500.html")



def base64_enc(plan_string):
    string_bytes = plan_string.encode("ascii")
    base64_bytes = base64.b64encode(string_bytes)
    valu = base64_bytes.decode("ascii")

    return valu

def base64_dec(plan_string):
    string_bytes = plan_string.encode("ascii")
    base64_bytes = base64.b64decode(string_bytes)
    valu = base64_bytes.decode("ascii")

    return valu



def mail_jet(newpassword,email_id,name):
    data = {
      'Messages': [
                    {
                            "From": {
                                    "Email": "jgallego@re-g.net",
                                    "Name": "Joel"
                            },
                            "To": [
                                    {
                                            "Email": str(email_id),
                                            "Name": str(name)
                                    }
                            ],
                            "Subject": "Password Reset Email",
                            "TextPart": "Dear Recipient, We have received your request for reset password.",
                            "HTMLPart": "<h3>Dear Recipient, We have received your request for reset password. !</h3><br />Your New Password : "+str(newpassword)+" <br><br><br>Regards, <br>Joel.<br><br><br>Note: This is a system generated e-mail, please do not reply to it.<br><br><br>*** This message is intended only for the person or entity to which it is addressed and may contain confidential and/or privileged information. If you have received this message in error, please notify the sender immediately and delete this message from your system ***"
                    }
            ]
    }
    result = mailjet.send.create(data=data)

    return (result.status_code)


@app.route('/')
def home():
    s = ""
    s += "select * from user_details"
    s += " WHERE"
    s += " role_type ='customer_admin'"
    db_conn = psycopg2.connect(dbcon)
    db_cursor = db_conn.cursor()
    db_cursor.execute(s)
    try:
        array_row = db_cursor.fetchone()
    except psycopg2.Error as e:
        error = "Database error: " + e + "/n SQL: " + s
        return render_template("user-login.html", error = error)
    if array_row == None:
        return render_template("user-login.html", cflag="true")
    else:
        return render_template("user-login.html", cflag="false")


@app.route('/forgot_password')
def forgot_password():
    return render_template("forgot_password.html")


@app.route('/reset_password',methods = ["GET","POST"])
def reset_password():
    try:
        error = None;
        if request.method == "POST":
            if request.form['email'] == "" or None:
                error = "Please Enter Email Id"
                return render_template("forgot_password.html", error = error)
            else:
                email_id = request.form['email']

                qury = ("select user_id,full_name from user_details where email_id = '"+str(email_id)+"' ;")
                conn = psycopg2.connect(dbcon)
                cur = conn.cursor()
                cur.execute(qury)
                r = cur.fetchone()

                if cur.rowcount == 1:
                    newpassword = (secrets.token_urlsafe(password_length))
                    newpasswordbase64 = base64_enc(newpassword)

                    mail_send = mail_jet(newpassword,email_id,str(r[1]))

                    if str(mail_send) ==  '200':
                        cur.execute("update user_details set password='"+str(newpasswordbase64)+"' where user_id = '"+str(r[0])+"';")
                        conn.commit()
                        cur.close()
                        conn.close()					
                        return render_template("user-login.html", info = "New password sent to "+str(email_id))
                    else:
                        cur.close()
                        conn.close()
                        return render_template("forgot_password.html", error = "Sorry ! We are unable reset your password now, please try again.")
                else:
                    cur.close()
                    conn.close()
                    return render_template("forgot_password.html", error = "Could not find your account")

    except Exception as e:
        logger.exception(e)
        return render_template("page500.html")
    

@app.route('/logout')
def logout():
    try:        
        response = redirect(url_for('home'))
        sessionkey = request.cookies.get('dada')
        db_conn = psycopg2.connect(dbcon)
        db_cursor = db_conn.cursor()
        sexpire = ""
        sexpire += "update user_details set session_id = 'signout', session_time = now()"+" where session_id ='"+str(sessionkey)+"';"
        db_cursor.execute(sexpire)
        db_conn.commit()
        db_cursor.close()
        db_conn.close()
        response.set_cookie('dada', expires=0)
        response.set_cookie('uid', expires=0)
        return response
    except Exception as e:
        logger.exception(e)
        return render_template("page500.html")  




@app.route('/login',methods = ["GET","POST"])
def login():
    try:
        error = None
        print ("going to login")
        if request.method == "POST":
            if request.form['email'] == "" or None:
                error = "Enter Email"
            elif request.form['pass'] == "" or None:
                error = "Enter Password"
            else:
                email_id = request.form['email']
                password = base64_enc(request.form['pass'])
                s = ""
                s += "select user_id,role_type,status,flag from user_details"
                s += " WHERE"
                s += " email_id ='" + email_id + "'"
                s += " AND"
                s += " password = '" + password + "'"
                db_conn = psycopg2.connect(dbcon)
                db_cursor = db_conn.cursor()
                db_cursor.execute(s)
                try:
                    array_row = db_cursor.fetchone()
                except psycopg2.Error as e:
                    error = "Database error: " + e + "/n SQL: " + s
                    return render_template("user-login.html", error = error)

                print (f"going to login dentroo array arow: {array_row}")
                if array_row == None:
                    return render_template('user-login.html',error="Invalid Login details")
                else:
                    user_id = array_row[0]
                    role_type = array_row[1]
                    status = array_row[2]
                    flag = array_row[3]
                    sessionkey=getSessionKey(email_id)
                    s1 = ""
                    s1 += "update user_details set session_id = '"+str(sessionkey)+"', session_time = now()"+" where user_id ='"+str(user_id)+"';"
                    db_cursor.execute(s1)
                    db_conn.commit()
                
                db_cursor.close()
                db_conn.close()
                flash("Welcome")

                print(f'role type is: {role_type}') 
                if role_type == 'super_admin' and status == 'active':
                    response = redirect(url_for('superadminhome'))

                elif role_type == 'user_admin' and status == 'active':
                    if flag == 'only_devices':
                        response = redirect(url_for('settings_p'))
                    else:
                        response = redirect(url_for('retreive'))
                elif role_type == 'customer_admin' and status == 'active':
                    response = redirect(url_for('retreive'))
                else:
                    return render_template("page500.html")
                expire_date = datetime.now()
                expire_date = expire_date + timedelta(seconds=1800)
                response.set_cookie('dada',sessionkey,expires=expire_date, path='/', samesite='None', secure=True)
                response.set_cookie('uid', expires=0)
                return response         

        return render_template('user-login.html',error=error)
    except Exception as e:
        logger.exception(e)
        return render_template("page500.html")



@app.route("/customerdetails", methods=["GET","POST"])
def superadminhome():
    try:
        sessionkey = request.cookies.get('dada')
        db_conn = psycopg2.connect(dbcon)
        sessionkey = validSession(db_conn, sessionkey)
        if sessionkey:
            s_table = []
            conn = psycopg2.connect(dbcon)
            cur = conn.cursor()

    
            cur.execute("""select role_type,full_name from user_details where session_id = '"""+str(sessionkey)+"""'""")
            r = cur.fetchone()
            full_name = r[1]
            if r[0] != 'super_admin':
                cur.close()
                conn.close()
                return render_template("page500.html")
                

            cur.execute("""select cid,customer_name,email_id,phone_number,state,country,status,lastupdate,city from customer_Details""")
            
            res = cur.fetchall()
            
                
            cur.close()
            conn.close()

             
            for r in res:
                s_table.append({
                "cid":str(r[0]),
                "cname":str(r[1]),
                "email":str(r[2]),
                "phone":str(r[3]),
                "city":str(r[8]),
                "state":str(r[4]),
                "country":str(r[5]),
                "status":str(r[6]),
                "lastupdate":str(r[7])[0:19]
                })
                 
         
            return render_template("customers.html", cdtls = s_table, full_name=full_name) 

        else:
            flash("Session expired, Please try again...!")
            return redirect(url_for('logout'))
    except Exception as e:
        logger.exception(e)
        return render_template("page500.html")




@app.route("/userdetails", methods=["GET","POST"])
def userdetails():
    try:
        sessionkey = request.cookies.get('dada')
        db_conn = psycopg2.connect(dbcon)
        sessionkey = validSession(db_conn, sessionkey)
        if sessionkey:
            s_table = []
            conn = psycopg2.connect(dbcon)
            cur = conn.cursor()

            cur.execute("""select role_type,user_id,colorname,bg_color,full_name,flag from user_details where session_id = '"""+str(sessionkey)+"""'""")
            r = cur.fetchone()


            user_c_id = r[1]
            role_type = r[0]
            full_name = r[4]
            flag = r[5]

            colorname = "primary"
            bg_color = "dark"
            if str(r[2]) in ['primary','blue','green','orange','red']:
                colorname = str(r[2])

            if str(r[3]) in ['dark','light']:
                bg_color = str(r[3])
            if role_type != 'customer_admin':
                cur.close()
                conn.close()
                return render_template("page500.html")


            cur.execute("""select u.cid,u.groups,ud.role_type from ucgm as u join 
                                    user_details ud on u.user_id = ud.user_id where  ud.session_id = '"""+str(sessionkey)+"""'""")
            ress = cur.fetchall()

            cur.execute("""select user_id,username,phone_number,email_id,role_type,status,session_time,city,state,country,full_name,flag 
                from user_details where user_id in (select user_id from ucgm where cid = '"""+str(ress[0][0])+"""') and role_type = 'user_admin' order by user_id""")

            res = cur.fetchall()
            cur.execute("select cid,customer_name from customer_details where cid = '"+str(ress[0][0])+"'")
            c_res = cur.fetchall()
            cur.close()
            conn.close()

             
            for r in res:
                s_table.append({
                "user_id":str(r[0]),
                "username":str(r[1]),
                "phone_number":str(r[2]),
                "email_id":str(r[3]),
                "role_type":str(r[4]),
                "status":str(r[5]),
                "session_time":str(r[6])[0:19],
                "city":str(r[7]),
                "state":str(r[8]),
                "country":str(r[9]),
                "full_name":str(r[10]),
                "cname":str(c_res[0][1]),
                "flags":str(r[11])
                })
                 
            c_d = []
            for c in c_res:
                c_d.append({
                    "cid":c[0],
                    "cn":c[1]
                    })


            return render_template("users.html",flag=flag,full_name=full_name, udtls = s_table, c_d = c_d, role_type=role_type, user_c_id=user_c_id, colorname=colorname, bg_color=bg_color) 

        else:
            flash("Session expired, Please try again...!")
            return redirect(url_for('logout'))
    except Exception as e:
        logger.exception(e)
        return render_template("page500.html")

# ------> 

# Configurazione SMTP (da personalizzare)
SMTP_SERVER = "smtp.mailserver.com"
SMTP_PORT = 587
SMTP_USERNAME = "your-email@example.com"
SMTP_PASSWORD = "your-email-password"
EMAIL_FROM = "your-email@example.com"
EMAIL_TO = ["recipient@example.com"]

# Funzione per inviare email
def send_email(subject, body):
    msg = MIMEMultipart()
    msg['From'] = EMAIL_FROM
    msg['To'] = ", ".join(EMAIL_TO)
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
        server.quit()
        print("✅ Email inviata con successo.")
    except Exception as e:
        print(f"❌ Errore durante l'invio dell'email: {e}")

# Controllo delle condizioni per l'invio automatico dell'email
def check_conditions_and_send_email(machine_id, top_notifications, machine_status):
    error_threshold = app.config.get('ERROR_THRESHOLD', 5)
    stop_threshold_minutes = app.config.get('STOP_THRESHOLD', 3)

    for key, (count, message) in top_notifications():
        if count >= error_threshold:
            subject = f"Allarme Frequente: {key}"
            body = f"L'errore '{message}' è stato rilevato {count} volte recentemente per la macchina {machine_id}."
            send_email(subject, body)

    if machine_status.get('stop', 0) >= stop_threshold_minutes * 60:
        subject = f"Impianto Fermo: {machine_id}"
        body = f"L'impianto '{machine_id}' è fermo da più di {stop_threshold_minutes} minuti."
        send_email(subject, body)


# ----------->        

def convert_time_to_hours(time_str):
    """Converte una stringa '2585h 0m' in ore totali (float)"""
    if not isinstance(time_str, str):  
        return 0  # Se il valore non è una stringa, restituisci 0
    
    match = re.match(r"(\d+)h (\d+)m", time_str)
    if match:
        hours, minutes = map(int, match.groups())
        return hours + (minutes / 60)  # Converte minuti in frazione d'ora
    return 0  # Default a 0 se il formato non corrisponde


@app.route("/dashboard", methods=["GET", "POST"])
def retreive():
    print("Going to dashboard")
    # Inizializza tutte le variabili necessarie con valori vuoti
    machine_idd = '-'  # Default value for machine_idd
    machine_namee = '-'  # Default value for machine_namee
    production_dates = []
    production_count = []
    current_cons = []
    daily_production_dates = []
    daily_production_count = []
    completed_tasks = []
    completed_tasks_dates = []
    state_times_numeric = {}
    top_notifications_dict = {}
    monthly_notifications_dict = []
    try:
        sessionkey = request.cookies.get('dada')
        print(f"Session key: {sessionkey}")
        if not sessionkey:
            flash("Session expired, please try again.")
            return redirect(url_for('logout'))
        
        machine_id = request.args.get('machine_id')
        print(f"📡 Device richiesto: {machine_id}")

        with psycopg2.connect(dbcon) as conn:
            with conn.cursor() as cur:
                # Validazione sessione
                sessionkey = validSession(conn, sessionkey)
                if not sessionkey:
                    flash("Session expired, please try again.")
                    return redirect(url_for('logout'))

                # Recupero dati utente
                cur.execute("""
                    SELECT u.cid, u.groups, ud.role_type, ud.full_name, ud.flag 
                    FROM ucgm u 
                    JOIN user_details ud ON u.user_id = ud.user_id 
                    WHERE ud.session_id = %s""", (sessionkey,))
                user = cur.fetchone()
                print (f"User in dashboard is: {user[1]}")

                if not user:
                    flash("User not found.")
                    return redirect(url_for('logout'))

                cid, groups, role_type, full_name, flag = user

                # Recupero gruppi utente
                allgroups = []
                if groups == 'all':
                    cur.execute("SELECT group_id FROM groups WHERE cid = %s", (cid,))
                    allgroups = [str(row[0]) for row in cur.fetchall()]
                else:
                    allgroups = groups.split(',')

                # Recupero dispositivi
                cur.execute(f"""
                    SELECT d.uid, d.address, d.group_id, g.group_name, d.cid, c.customer_name,
                           l.power_on, l.run, l.stop, l.alarm, l.pause, l.emergency, l.picesmade,
                           l.current_consumption_kw, l.alarm_mach, l.lat, l.lng, l.lastupdate,
                           d.machine_name, CASE WHEN l.lastupdate IS NOT NULL THEN 'Connected' ELSE 'Not Connected' END,
                           d.token, d.city, d.country, d.state, d.machine_info
                    FROM devices d
                    JOIN customer_details c ON d.cid = c.cid
                    JOIN groups g ON d.group_id = g.group_id
                    JOIN ucgm uc ON d.cid = uc.cid
                    JOIN user_details u ON uc.user_id = u.user_id
                    LEFT JOIN live_data l ON CAST(l.idmach AS VARCHAR) = d.uid
                    WHERE u.session_id = %s AND d.group_id = ANY(%s::int[])
                    ORDER BY d.uid
                """, (sessionkey, allgroups))

                devices = cur.fetchall()

                # Usa il machine_id passato, altrimenti usa il primo disponibile
              # if not machine_id and devices:
                #    machine_id = devices[0][0]

                # Recupero impostazioni utente
                cur.execute("""
                    SELECT user_id, username, colorname, bg_color 
                    FROM user_details 
                    WHERE session_id = %s
                """, (sessionkey,))
                user_settings = cur.fetchone()

                user_c_id, username, colorname, bg_color = user_settings
                colorname = colorname if colorname in ['primary', 'blue', 'green', 'orange', 'red'] else 'primary'
                bg_color = bg_color if bg_color in ['dark', 'light'] else 'dark'

                # Se ci sono dispositivi, recupera dati di produzione
                if not machine_id and devices:
                    machine_id = devices[0][0]
                    print(f"📡 Machine richiesto: {machine_id}")

                #if machine_id:
                    cur.execute("""
                        SELECT l.idmach, l.picesmade, l.lastupdate, l.current_consumption_kw, d.machine_name, l.task_number
                        FROM live_data_log l
                        JOIN devices d ON d.uid = l.idmach
                        WHERE l.idmach = %s
                        ORDER BY l.lastupdate DESC
                    """, (machine_id,))
                    results3 = cur.fetchall()

                    # Daily Pieces
                    cur.execute("""
                        SELECT program_number, SUM(daily_pices), DATE(lastupdate)
                        FROM daily_pices_log
                        WHERE idmach = %s
                        GROUP BY program_number, DATE(lastupdate)
                        ORDER BY DATE(lastupdate) DESC
                    """, (machine_id,))
                    daily_pices_res = cur.fetchall()

                    #Status of machine logs for last 24 months
                    cur.execute(f"""
                        SELECT d.uid, d.machine_name, l.run, l.stop, l.alarm, l.pause, l.emergency, l.lastupdate
                        FROM devices d
                        JOIN live_data_log l ON CAST(l.idmach AS VARCHAR) = d.uid
                        WHERE l.idmach = %s
                        AND l.lastupdate >= CURRENT_DATE - INTERVAL '24 months'
                        ORDER BY d.uid, l.lastupdate
                    """, (machine_id,))
                    state_logs = cur.fetchall()

                    # **** Notificationa *****
                    # Recupero notifiche degli ultimi 6 mesi
                    cur.execute("""
                        SELECT idmach, notification_type, txt,
                            COUNT(*) AS count
                        FROM notification
                        WHERE lastupdate >= CURRENT_DATE - INTERVAL '24 months'
                            AND idmach = %s
                        GROUP BY idmach, notification_type, txt
                        ORDER BY count DESC
                        LIMIT 10;
                    """,(machine_id,))
                    top_notifications = cur.fetchall()

                    # Estrarre il numero totale di notifiche per ogni mese negli ultimi 6 mesi
                    cur.execute("""
                        SELECT DATE_TRUNC('month', lastupdate) AS month, COUNT(*)
                        FROM notification
                        WHERE lastupdate >= CURRENT_DATE - INTERVAL '24 months'
                        AND idmach = %s
                        GROUP BY month
                        ORDER BY month DESC
                    """,(machine_id,))
                    monthly_notifications = cur.fetchall()

                    print(f"📡 Machine ID selezionato: {machine_id}")

                    # exract data
                    # Converti results3 e daily_pices_res in DataFrame
                    results3_df = pd.DataFrame(results3, columns=['machine_idd', 'picesmade', 'lastupdate', 'consumption', 'machine_name', 'task_number'])
                    daily_pices_df = pd.DataFrame(daily_pices_res, columns=['program_number', 'daily_pices', 'lastupdate'])

                    # Estrazione sicura delle informazioni della macchina
                    machine_idd = results3_df['machine_idd'].iloc[0] if not results3_df.empty else '-'
                    machine_namee = results3_df['machine_name'].iloc[0] if not results3_df.empty else '-'

                    # **Conversione delle date con fuso orario in UTC**
                    results3_df['lastupdate'] = pd.to_datetime(results3_df['lastupdate'], utc=True).dt.tz_localize(None)
                    daily_pices_df['lastupdate'] = pd.to_datetime(daily_pices_df['lastupdate'], utc=True).dt.tz_localize(None)

                    # **1. Produzione Mensile** 
                    # **1. Somma della produzione mensile fino alla fine del mese**
                    # ✅ Convertiamo 'lastupdate' in formato mensile
                    results3_df['month'] = results3_df['lastupdate'].dt.to_period('M')
                    
                    # 📌 **Calcoliamo la Produzione Totale Mensile sommando tutti i giorni del mese**
                    production_df = results3_df.groupby('month').agg({
                        'picesmade': 'sum',        # Somma totale pezzi prodotti nel mese
                        'consumption': 'sum'       # Somma totale del consumo nel mese
                    }).reset_index()
                    
                    # 🔄 Convertiamo il periodo mensile in stringa per JSON
                    production_df['month'] = production_df['month'].astype(str)

                    production_dates = production_df['month'].tolist()
                    production_count = production_df['picesmade'].tolist()
                    current_cons = production_df['consumption'].tolist()

                    # **2. Produzione Giornaliera**
                    daily_production_df = daily_pices_df.groupby(daily_pices_df['lastupdate'].dt.to_period('D')).agg({
                        'daily_pices': 'sum'
                    }).reset_index()

                    daily_production_dates = daily_production_df['lastupdate'].astype(str).tolist()
                    daily_production_count = daily_production_df['daily_pices'].tolist()

                    # **3. TAsk/commesse Completate**
                    completed_tasks_df = results3_df.drop_duplicates(subset=['lastupdate', 'task_number'])

                    completed_tasks_count = completed_tasks_df.groupby(completed_tasks_df['lastupdate'].dt.to_period('M')).size().reset_index(name='completed_tasks')

                    completed_tasks_dates = completed_tasks_count['lastupdate'].astype(str).tolist()
                    completed_tasks = completed_tasks_count['completed_tasks'].tolist()

                    ###
                    # Creazione di un dizionario per sommare i tempi degli stati
 
                    state_times = defaultdict(lambda: {'run': 0, 'stop': 0, 'alarm': 0, 'pause': 0, 'emergency': 0})
                    prev_state = {}

                    for uid, machine_name, run, stop, alarm, pause, emergency, lastupdate in state_logs:
                        if uid not in prev_state:
                            prev_state[uid] = {'time': lastupdate, 'run': run, 'stop': stop, 'alarm': alarm, 'pause': pause, 'emergency': emergency}
                        else:
                            time_diff = (lastupdate - prev_state[uid]['time']).total_seconds()
                            if prev_state[uid]['run']: state_times[uid]['run'] += time_diff
                            if prev_state[uid]['stop']: state_times[uid]['stop'] += time_diff
                            if prev_state[uid]['alarm']: state_times[uid]['alarm'] += time_diff
                            if prev_state[uid]['pause']: state_times[uid]['pause'] += time_diff
                            if prev_state[uid]['emergency']: state_times[uid]['emergency'] += time_diff
                            
                            prev_state[uid] = {'time': lastupdate, 'run': run, 'stop': stop, 'alarm': alarm, 'pause': pause, 'emergency': emergency}

                    # Convertire i secondi in ore e minuti
                    for uid in state_times:
                        for key in state_times[uid]:
                            hours = int(state_times[uid][key] // 3600)
                            minutes = int((state_times[uid][key] % 3600) // 60)
                            state_times[uid][key] = f"{hours}h {minutes}m"

                    # Convertiamo state_times in numeri prima di inviarlo al frontend
                    state_times_numeric = {
                        key: {k: convert_time_to_hours(v) for k, v in value.items() if v is not None}  # Evita None
                        for key, value in state_times.items()
                    }
                    ###
                    state_times_ = json.dumps(state_times_numeric)

                    # Convertire i risultati in dizionari utilizzabili in JSON
                    top_notifications_dict = {f"{row[1]}: {row[2]}": row[3] for row in top_notifications}
                    monthly_notifications_dict = {row[0].strftime("%Y-%m"): row[1] for row in monthly_notifications}

                    # to send e-mails notifications

                    #check_conditions_and_send_email(machine_id, top_notifications_dict, state_times_)

                    # Verifica output
                    print(f"Production Dates: {production_dates}")
                    print(f"Production Count: {production_count}")
                    print(f"Current Consumption: {current_cons}")
                    print(f"Daily Production Dates: {daily_production_dates}")
                    print(f"Daily Production Count: {daily_production_count}")
                    print(f"Completed Tasks Dates: {completed_tasks_dates}")
                    print(f"Completed Tasks: {completed_tasks}")
                    print(f"State Times: {state_times_}")
                    print(f"Top Notifications: {top_notifications_dict}")
                    print(f"Monthly Notifications: {monthly_notifications_dict}")


                # Costruzione tabella dispositivi
                def safe_str(value):
                    """Converte i valori None o 'None' in '-' e restituisce la stringa altrimenti."""
                    return str(value) if value not in [None, 'None'] else '-'

                s_table = [{
                    'sno': i + 1,
                    'uid': safe_str(d[0]),
                    'address': safe_str(d[1]),
                    'group_id': safe_str(d[2]),
                    'group_name': safe_str(d[3]),
                    'cid': safe_str(d[4]),
                    'customer_name': safe_str(d[5]),
                    'power_on': safe_str(d[6]),
                    'run': safe_str(d[7]),
                    'stop': safe_str(d[8]),
                    'alarm': safe_str(d[9]),
                    'pause': safe_str(d[10]),
                    'emergency': safe_str(d[11]),
                    'picesmade': safe_str(d[12]),
                    'current_consumption_kw': safe_str(d[13]),
                    'alarm_mach': safe_str(d[14]),
                    'lat': safe_str(d[15]),
                    'lng': safe_str(d[16]),
                    'lastupdate': d[17].strftime("%Y-%m-%d %H:%M:%S") if d[17] else '-',
                    'machine_name': safe_str(d[18]),
                    'machine_connected': safe_str(d[19]),
                    'token': safe_str(d[20]),
                    'city': safe_str(d[21]),
                    'country': safe_str(d[22]),
                    'state': safe_str(d[23]),
                    'machine_info': safe_str(d[24])
                } for i, d in enumerate(devices)]


        # Inversione delle liste per ordine cronologico
        #production_dates.reverse()
        production_count.reverse()
        current_cons.reverse()
        #state_times_.reverse()
        completed_tasks.reverse()
        completed_tasks_dates.reverse()
        daily_production_count.reverse()
        daily_production_dates.reverse()

        # Rendering del template
        return render_template(
            "dashboard.html",
            flag=flag,
            full_name=full_name,
            s_table=s_table,
            machine_idd=machine_idd,
            machine_namee=machine_namee,
            production_dates=production_dates,
            production_count=production_count,
            current_cons=state_times_numeric,
            #state_times=state_times_,
            completed_tasks=completed_tasks,
            role_type=role_type,
            colorname=colorname,
            user_c_id=user_c_id,
            bg_color=bg_color,
            completed_tasks_dates=completed_tasks_dates,
            daily_production_dates=daily_production_dates,
            daily_production_count=daily_production_count,
            top_notifications=top_notifications_dict,  # 🔥 Passiamo le 10 notifiche più comuni
            monthly_notifications=monthly_notifications_dict
        )
    
        '''return jsonify({
            "flag":flag,
            "full_name":full_name,
            "s_table":s_table,
            "machine_idd":machine_idd,
            "machine_namee":machine_namee,
            "production_dates":production_dates,
            "production_count":production_count,
            "current_cons":state_times_numeric,
            #state_times=state_times_,
            "completed_tasks":completed_tasks,
            "role_type":role_type,
            "colorname":colorname,
            "user_c_id":user_c_id,
            "bg_color":bg_color,
            "completed_tasks_dates":completed_tasks_dates,
            "daily_production_dates":daily_production_dates,
            "daily_production_count":daily_production_count,
            "top_notifications":top_notifications_dict,  # 🔥 Passiamo le 10 notifiche più comuni
            "monthly_notifications":monthly_notifications_dict
            })'''


    except Exception as e:
        logger.exception(e)
        return render_template("page500.html")






@app.route("/statics", methods=["GET","POST"])
def statics():
    try:
        sessionkey = request.cookies.get('dada')
        db_conn = psycopg2.connect(dbcon)
        sessionkey = validSession(db_conn, sessionkey)
        if sessionkey:
            s_table = []
            payload = []
            data = {}
            data["heading"] = "LOCATION NAME"
            data["mapinfo"] = []
            conn = psycopg2.connect(dbcon)
            cur = conn.cursor()
            cur.execute("""select u.cid,u.groups,ud.role_type,ud.full_name,ud.flag from ucgm as u join 
                                    user_details ud on u.user_id = ud.user_id where  ud.session_id = '"""+str(sessionkey)+"""'""")
            res = cur.fetchall()
            for r in res:
                cid = r[0]
                role_type = r[2]
                full_name=r[3]
                flag=r[4]
                allgroups = []
                if r[1] == 'all':
                    cur.execute("select group_id from groups where cid in ('"+str(cid)+"')")
                    res2 = cur.fetchall()
                    if len(res2) == 0:
                        allgroups.append(0)
                        allgroups.append(0)
                    else:
                        for r2 in res2:
                            allgroups.append(str(r2[0]))
                            allgroups.append(0)   
                else:
                    b = (res[0][1]).split(',')
                    for c in b:
                        allgroups.append(c)
                        allgroups.append(0)    
                cur.execute("""  select d.uid,d.address,d.group_id,g.group_name,d.cid,c.customer_name,
                                    l.power_on,l.run,l.stop,l.alarm,l.pause,l.emergency,l.picesmade,l.current_consumption_kw,l.alarm_mach,l.lat,l.lng,l.lastupdate,
                                    d.machine_name,CASE when l.lastupdate is not null then 'Connected' else 'Not Connected' END,d.token,d.city,d.country,d.state,d.machine_info

                                    from devices d join customer_details c on d.cid=c.cid join groups g on d.group_id=g.group_id
                                    join ucgm uc on d.cid =uc.cid join user_details u on uc.user_id = u.user_id 
                                    left join live_data l on cast (l.idmach as varchar) =d.uid 
                                    where u.session_id = '"""+str(sessionkey)+"""'
                                    and d.group_id in """+str(tuple(allgroups))+""" order by 1""")
                results = cur.fetchall()
                cur.execute(""" select user_id,username,colorname,bg_color from user_details where session_id = '"""+str(sessionkey)+"""'""")
                results2 = cur.fetchall()


                machine_idd = ""
                machine_namee = ""
                production_dates = []
                production_count = []
                daily_production_dates = []
                daily_production_count = []
                current_cons = []
                completed_tasks = []
                completed_tasks_dates = []

                colorname = "primary"
                bg_color = "dark"
                for result2 in results2:
                    username = str(result2[1])
                    user_c_id = str(result2[0])
                    if str(result2[2]) in ['primary','blue','green','orange','red']:
                        colorname = str(result2[2])

                    if str(result2[3]) in ['dark','light']:
                        bg_color = str(result2[3])

                if len(results) != 0:
                    cur.execute("select l.idmach,l.picesmade,l.lastupdate as varchar,l.current_consumption_kw,d.machine_name,l.task_number from  live_data_log l join devices d on d.uid=l.idmach where l.idmach = '"+str(results[0][0])+"' order by l.lastupdate desc")
                    results3 = cur.fetchall()

                    cur.execute("select l.idmach,l.picesmade,l.lastupdate as varchar,l.current_consumption_kw,d.machine_name,l.task_number from  live_data_log l join devices d on d.uid = l.idmach where l.idmach = '"+str(results[0][0])+"' order by l.lastupdate desc")
                    results_dailyprod = cur.fetchall()

                    cur.execute("select program_number,sum(daily_pices),DATE(lastupdate) from daily_pices_log where idmach = '"+str(results[0][0])+"' GROUP BY program_number,DATE(lastupdate) order by DATE(lastupdate) desc ")

                    daily_pices_res = cur.fetchall()

                    

                    for h in results3:
                        machine_idd =str(h[0])
                        machine_namee = str(h[4])
                        if (months[int(str(h[2])[0:7].split('-')[1])]+'-'+str(h[2])[0:7].split('-')[0]) not in production_dates:
                            # production_dates.append((months[int(str(h[2])[0:7].split('-')[1])]+'-'+str(h[2])[0:7].split('-')[0]))
                            # production_count.append(int(h[1]))
                            current_cons.append(float(h[3]))
                            # completed_tasks.append(1)
                        else:
                            # production_count[(production_dates.index((months[int(str(h[2])[0:7].split('-')[1])]+'-'+str(h[2])[0:7].split('-')[0])))] += int(h[1])
                            current_cons[(production_dates.index((months[int(str(h[2])[0:7].split('-')[1])]+'-'+str(h[2])[0:7].split('-')[0])))] += float(h[3])
                            # completed_tasks[(production_dates.index((months[int(str(h[2])[0:7].split('-')[1])]+'-'+str(h[2])[0:7].split('-')[0])))] += 1
                    

                    for h in daily_pices_res:
                        if (months[int(str(h[2])[0:7].split('-')[1])]+'-'+str(h[2])[0:7].split('-')[0]) not in production_dates:
                            production_dates.append((months[int(str(h[2])[0:7].split('-')[1])]+'-'+str(h[2])[0:7].split('-')[0]))
                            production_count.append(int(h[1]))
                        else:
                            production_count[(production_dates.index((months[int(str(h[2])[0:7].split('-')[1])]+'-'+str(h[2])[0:7].split('-')[0])))] += int(h[1])


                    for h in daily_pices_res:						
                        if (str(h[2])[0:10]) not in daily_production_dates:
                            daily_production_dates.append(str(h[2])[0:10])
                            daily_production_count.append(int(h[1]))
                        else:
                            daily_production_count[(daily_production_dates.index(str(h[2])[0:10]))] += int(h[1])

                    cmpltd_tasks = []
                    for l in results3:
                        if (months[int(str(l[2])[0:7].split('-')[1])]+'-'+str(l[2])[0:7].split('-')[0]) not in completed_tasks_dates:
                            completed_tasks_dates.append((months[int(str(l[2])[0:7].split('-')[1])]+'-'+str(l[2])[0:7].split('-')[0]))
                            if l[5] not in cmpltd_tasks:
                                cmpltd_tasks.append(l[5])
                                completed_tasks.append(1)
                            else:
                                completed_tasks.append(0)
                        else:
                            if l[5] not in cmpltd_tasks:
                                cmpltd_tasks.append(l[5])
                                completed_tasks[(completed_tasks_dates.index((months[int(str(l[2])[0:7].split('-')[1])]+'-'+str(l[2])[0:7].split('-')[0])))] += 1

                
                    i = 0   
                    for result in results:
                        i += 1          
                        s_table.append(
                            {'sno':str(i),
                            'uid':str(result[0]),
                            'address':str(result[1]) if str(result[1]) != 'None' else '-',
                            'group_id':str(result[2]) if str(result[2]) != 'None' else '-',
                            'group_name':str(result[3]) if str(result[3]) != 'None' else '-',
                            'cid':str(result[4]) if str(result[4]) != 'None' else '-',
                            'customer_name':str(result[5]) if str(result[5]) != 'None' else '-',
                            'power_on': str(result[6]) if str(result[6]) != 'None' else '-',
                            'run': str(result[7]) if str(result[7]) != 'None' else '-',
                            'stop': str(result[8]) if str(result[8]) != 'None' else '-',
                            'alarm': str(result[9]) if str(result[9]) != 'None' else '-',
                            'pause': str(result[10]) if str(result[10]) != 'None' else '-',
                            'emergency': str(result[11]) if str(result[11]) != 'None' else '-',
                            'picesmade': str(result[12]) if str(result[12]) != 'None' else '-',
                            'current_consumption_kw': str(result[13]) if str(result[13]) != 'None' else '-',
                            'alarm_mach': str(result[14]) if str(result[14]) != 'None' else '-',
                            'lat': str(result[15]) if str(result[15]) != 'None' else '-',
                            'lng': str(result[16]) if str(result[16]) != 'None' else '-',
                            'lastupdate': str(result[17])[0:19] if str(result[17]) != 'None' else '-',
                            'machine_name':str(result[18]) if str(result[18]) != 'None' else '-',
                            'machine_connected':str(result[19]) if str(result[19]) != 'None' else '-',
                            'token':str(result[20]) if str(result[20]) != 'None' else '-',
                            'city':str(result[21]) if str(result[21]) != 'None' else '-',
                            'country':str(result[22]) if str(result[22]) != 'None' else '-',
                            'state':str(result[23]) if str(result[23]) != 'None' else '-',
                            'machine_info':str(result[24]) if str(result[24]) != 'None' else '-'						

                                           
                            })    



                
                            

            cur.close()
            conn.close()


            production_dates.reverse()
            production_count.reverse()
            current_cons.reverse()
            completed_tasks.reverse()
            completed_tasks_dates.reverse()
            daily_production_dates.reverse()
            daily_production_count.reverse()



            return render_template("statics.html",flag=flag, full_name=full_name, s_table=s_table,machine_idd = machine_idd, machine_namee=machine_namee, production_dates=production_dates, production_count=production_count,current_cons=current_cons,
completed_tasks=completed_tasks,role_type=role_type,user_c_id=user_c_id,colorname=colorname, bg_color=bg_color,completed_tasks_dates=completed_tasks_dates,daily_production_dates=daily_production_dates,daily_production_count=daily_production_count) 
        else:
            flash("session expired, Please try again...!")
            return redirect(url_for('logout'))
    except Exception as e:
        logger.exception(e)
        return render_template("page500.html")



@app.route("/get_gr", methods=["GET", "POST"])
#@cache.cached(timeout=60, query_string=True)
def retreive33():
    try:
        sessionkey = request.cookies.get('dada')
        db_conn = psycopg2.connect(dbcon)
        sessionkey = validSession(db_conn, sessionkey)
        if not sessionkey:
            flash("Session expired, please try again...!")
            return redirect(url_for('logout'))

        machine_id_req = request.args.get('machine_id')

        with psycopg2.connect(dbcon) as conn:
            with conn.cursor() as cur:
                # Query unica per live data
                start_time = time.time()
                cur.execute("""
                    SELECT l.idmach, l.picesmade, l.lastupdate, l.current_consumption_kw, d.machine_name, l.task_number 
                    FROM live_data_log l 
                    JOIN devices d ON d.uid = l.idmach 
                    WHERE l.idmach = %s 
                    ORDER BY l.lastupdate DESC
                """, (machine_id_req,))
                results3 = cur.fetchall()
                end_time = time.time()
                print(f"Tempo di esecuzione query: {end_time - start_time:.4f} secondi")

                # Query ottimizzata per daily pieces
                cur.execute("""
                    SELECT program_number, SUM(daily_pices), DATE(lastupdate) 
                    FROM daily_pices_log 
                    WHERE idmach = %s 
                    GROUP BY program_number, DATE(lastupdate) 
                    ORDER BY DATE(lastupdate) DESC
                """, (machine_id_req,))
                daily_pices_res = cur.fetchall()

        # Elaborazione risultati
        machine_idd = results3[0][0] if results3 else ""
        machine_namee = results3[0][4] if results3 else ""

        production_dates = {}
        current_cons = []
        completed_tasks = {}
        daily_production_dates = {}
        daily_production_count = []

        for h in results3:
            date_key = h[2].strftime("%Y-%m")
            production_dates[date_key] = production_dates.get(date_key, 0) + h[1]
            current_cons.append(float(h[3]))
            completed_tasks[date_key] = completed_tasks.get(date_key, 0) + 1

        for h in daily_pices_res:
            date_str = h[2].strftime("%Y-%m-%d")
            daily_production_dates[date_str] = daily_production_dates.get(date_str, 0) + h[1]

        # Preparazione risposta
        return jsonify({
            "machine_idd": machine_idd,
            "machine_namee": machine_namee,
            "production_dates": list(production_dates.keys()),
            "production_count": list(production_dates.values()),
            "current_cons": current_cons,
            "completed_tasks": list(completed_tasks.values()),
            "completed_tasks_dates": list(completed_tasks.keys()),
            "daily_production_dates": list(daily_production_dates.keys()),
            "daily_production_count": list(daily_production_dates.values())
        })

    except Exception as e:
        logger.exception(e)
        return render_template("page500.html")



@app.route("/get_gr_dt", methods=["GET","POST"])
def retreive333():
    try:
        sessionkey = request.cookies.get('dada')
        db_conn = psycopg2.connect(dbcon)
        sessionkey = validSession(db_conn, sessionkey)
        if sessionkey:
            machine_id_req = request.args.get('machine_id')
            fromdate_req = request.args.get('fromdate')
            todate_req = request.args.get('todate')
            s_table = []
            payload = []
            data = {}
            data["heading"] = "LOCATION NAME"
            data["mapinfo"] = []
            conn = psycopg2.connect(dbcon)
            cur = conn.cursor()


            cur.execute("select l.idmach,l.picesmade,l.lastupdate,l.current_consumption_kw,d.machine_name,l.task_number from  live_data_log l join devices d on d.uid=l.idmach where l.idmach = '"+str(machine_id_req)+"' and l.lastupdate between '"+str(fromdate_req)+" 00:00:00' and '"+str(todate_req)+" 23:59:59' order by l.lastupdate desc")
            results3 = cur.fetchall()

            cur.execute("select l.idmach,l.picesmade,l.lastupdate,l.current_consumption_kw,d.machine_name,l.task_number from  live_data_log l join devices d on d.uid=l.idmach where l.idmach = '"+str(machine_id_req)+"' and l.lastupdate between '"+str(fromdate_req)+" 00:00:00' and '"+str(todate_req)+" 23:59:59' order by l.lastupdate desc")
            results_dailyprod = cur.fetchall()

            cur.execute("select program_number,sum(daily_pices),DATE(lastupdate) from daily_pices_log where idmach = '"+str(machine_id_req)+"' and lastupdate between '"+str(fromdate_req)+" 00:00:00' and '"+str(todate_req)+" 23:59:59'  GROUP BY program_number,DATE(lastupdate) order by DATE(lastupdate) desc")

            daily_pices_res = cur.fetchall()

            machine_idd = ""
            machine_namee = ""
            production_dates = []
            production_count = []
            daily_production_dates = []
            daily_production_count = []
            current_cons = []
            completed_tasks = []
            completed_tasks_dates=[]

            for h in results3:
                machine_idd =str(h[0])
                machine_namee=str(h[4])
                if (months[int(str(h[2])[0:7].split('-')[1])]+'-'+str(h[2])[0:7].split('-')[0]) not in production_dates:
                    # production_dates.append((months[int(str(h[2])[0:7].split('-')[1])]+'-'+str(h[2])[0:7].split('-')[0]))
                    # production_count.append(int(h[1]))
                    current_cons.append(float(h[3]))
                    # completed_tasks.append(1)
                else:
                    # production_count[(production_dates.index((months[int(str(h[2])[0:7].split('-')[1])]+'-'+str(h[2])[0:7].split('-')[0])))] += int(h[1])
                    current_cons[(production_dates.index((months[int(str(h[2])[0:7].split('-')[1])]+'-'+str(h[2])[0:7].split('-')[0])))] += float(h[3])
                    # completed_tasks[(production_dates.index((months[int(str(h[2])[0:7].split('-')[1])]+'-'+str(h[2])[0:7].split('-')[0])))] += 1	
            
            for h in daily_pices_res:
                if (months[int(str(h[2])[0:7].split('-')[1])]+'-'+str(h[2])[0:7].split('-')[0]) not in production_dates:
                    production_dates.append((months[int(str(h[2])[0:7].split('-')[1])]+'-'+str(h[2])[0:7].split('-')[0]))
                    production_count.append(int(h[1]))
                else:
                    production_count[(production_dates.index((months[int(str(h[2])[0:7].split('-')[1])]+'-'+str(h[2])[0:7].split('-')[0])))] += int(h[1])

            cmpltd_tasks = []
            
            for l in results3:
                if (months[int(str(l[2])[0:7].split('-')[1])]+'-'+str(l[2])[0:7].split('-')[0]) not in completed_tasks_dates:
                    completed_tasks_dates.append((months[int(str(l[2])[0:7].split('-')[1])]+'-'+str(l[2])[0:7].split('-')[0]))
                    if l[5] not in cmpltd_tasks:
                        cmpltd_tasks.append(l[5])
                        completed_tasks.append(1)
                    else:
                        completed_tasks.append(0)
                else:
                    if l[5] not in cmpltd_tasks:
                        cmpltd_tasks.append(l[5])
                        completed_tasks[(completed_tasks_dates.index((months[int(str(l[2])[0:7].split('-')[1])]+'-'+str(l[2])[0:7].split('-')[0])))] += 1						

            for h in daily_pices_res:						
                if (str(h[2])[0:10]) not in daily_production_dates:
                    daily_production_dates.append(str(h[2])[0:10])
                    daily_production_count.append(int(h[1]))
                else:
                    daily_production_count[(daily_production_dates.index(str(h[2])[0:10]))] += int(h[1])
            cur.close()
            conn.close()

            production_dates.reverse()
            production_count.reverse()
            daily_production_dates.reverse()
            daily_production_count.reverse()
            current_cons.reverse()
            completed_tasks.reverse()
            completed_tasks_dates.reverse()


            
            return jsonify({"machine_idd":machine_idd,"machine_namee":machine_namee, "production_dates":production_dates,"production_count":production_count,"current_cons":current_cons,
"completed_tasks":completed_tasks,"completed_tasks_dates":completed_tasks_dates,"daily_production_count":daily_production_count,"daily_production_dates":daily_production_dates}) 
        else:
            flash("session expired, Please try again...!")
            return redirect(url_for('logout'))
    except Exception as e:
        logger.exception(e)
        return render_template("page500.html")





@app.route("/get_gr_dt_report", methods=["GET","POST"])
def retreive_report():
    try:
        sessionkey = request.cookies.get('dada')
        db_conn = psycopg2.connect(dbcon)
        sessionkey = validSession(db_conn, sessionkey)
        if sessionkey:
            machine_id_req = request.args.get('machine_id')
            fromdate_req = request.args.get('fromdate')
            todate_req = request.args.get('todate')
            report = request.args.get('report')
            s_table = []
            payload = []
            data = {}
            data["heading"] = "LOCATION NAME"
            data["mapinfo"] = []
            conn = psycopg2.connect(dbcon)
            cur = conn.cursor()
            cur.execute("select idmach,power_on,run,stop,alarm,emergency,picesmade,current_consumption_kw,task_number,alarm_mach,mapcord,axes_x,axes_y,axes_z,axes_r,lat,lng,lastupdate from  live_data_log where idmach = '"+str(machine_id_req)+"' and lastupdate between '"+str(fromdate_req)+" 00:00:00' and '"+str(todate_req)+" 23:59:59' order by lastupdate asc")
            results = cur.fetchall()

            cur.execute("select CAST(COALESCE(sum(daily_pices),0) as integer) from daily_pices_log where idmach = '"+str(machine_id_req)+"' and lastupdate between '"+str(fromdate_req)+" 00:00:00' and '"+str(todate_req)+" 23:59:59'")					
            total_pices = cur.fetchall()
            

            cur.close()
            conn.close()
            if report == "datatransferred":
                def generate():
                    head = ["","","","","","DATA TRASNFERRED","","","","",""]
                    yield ','.join(head) + "\r\n"
                    dt = ["","","","","","Report from "+fromdate_req+" to "+todate_req,"","","","",""]
                    yield ','.join(dt) + "\r\n"
                    log_columns = ["idmach","power_on","run","stop","alarm","emergency","picesmade","current_consumption_kw","task_number","alarm_mach","lastupdate"]
                    yield ','.join(log_columns) + "\r\n"
                    for r in results:
                        yield str(r[0])+","+str(r[1])+","+str(r[2])+","+str(r[3])+","+str(r[4])+","+str(r[5])+","+str(r[6])+","+str(r[7])+","+str(r[8])+","+str(r[9])+","+str(r[17])[0:19]+"\r\n"
                return Response(generate(), mimetype='text/csv');
            
            elif report == "analyticsstatus":

                tasknum = []
                for i in results:
                    if i[8] not in tasknum:
                        tasknum.append(i[8])

                def total_hrs(results,indx):
                    total_hrs = 0
                    startdate = None
                    
                    if indx == 6:
                        for i in total_pices[0]:
                            total_hrs += i
                    elif indx == 7:
                        for i in results:
                            total_hrs += i[indx]
                    else:
                        cnt = 0
                        for i in results:
                            if i[indx] == 1 and startdate == None:
                                startdate = i[17]
                            elif i[indx] == 0 and startdate != None:
                                total_hrs += ((i[17]-startdate).total_seconds())/3600
                                startdate = None
                            elif cnt == len(results)-1 and (results[len(results)-1][indx]) == 1:
                                total_hrs += ((i[17]-startdate).total_seconds())/3600
                            cnt +=1
                    return total_hrs


                power_on_time = total_hrs(results,1)
                run_time = total_hrs(results,2)
                stop_time = total_hrs(results,3)
                alarm_time = total_hrs(results,4)
                emergency_time = total_hrs(results,5)
                picesmade = total_hrs(results,6)
                total_current_consumption_kw = total_hrs(results,7)
                def generate():					
                    head = ["","","","","","ANALYTICS STATUS","","","","",""]
                    yield ','.join(head) + "\r\n"
                    dt = ["","","","","","Report from "+fromdate_req+" to "+todate_req,"","","","",""]
                    yield ','.join(dt) + "\r\n"
                    log_columns = ["idmach","power_on time","run time","stop time","alarm time","emergency time","picesmade","current_consumption_kw","total no. of task_numbers"]
                    yield ','.join(log_columns) + "\r\n"
                    body = [str(results[0][0]),str(round(power_on_time))+'h',str(round(run_time))+'h',str(round(stop_time))+'h',str(round(alarm_time))+'h',str(round(emergency_time))+'h',str(picesmade),str(round(total_current_consumption_kw)),str(len(tasknum))]
                    yield ','.join(body) + "\r\n"
                return Response(generate(), mimetype='text/csv');

            elif report == "alarmstatus":
                alarm_mach = []
                for i in results:
                    alarm_mach.append(i[9])

                def generate():			
                    head = ["","ALARAM STATUS",""]
                    yield ','.join(head) + "\r\n"
                    dt = ["","Report from "+fromdate_req+" to "+todate_req,""]
                    yield ','.join(dt) + "\r\n"
                    log_columns = ["idmach","alarm_mach","count"]
                    yield ','.join(log_columns) + "\r\n"
                    my_dict = {i:alarm_mach.count(i) for i in alarm_mach}
                    for a in my_dict:
                        yield str(results[0][0])+','+str(a)+','+str(my_dict[a])+'\r\n'
                return Response(generate(), mimetype='text/csv');
            else:
                def generate():			
                    head = ["","","","","","INVALID REPORT","","","","",""]
                    yield ','.join(head) + "\r\n"
                    dt = ["","","","","","Report from "+fromdate_req+" to "+todate_req,"","","","",""]
                    yield ','.join(dt) + "\r\n"
                return Response(generate(), mimetype='text/csv');

        else:
            flash("session expired, Please try again...!")
            return redirect(url_for('logout'))
    except Exception as e:
        logger.exception(e)
        return render_template("page500.html")







@app.route("/devices", methods=["GET","POST"])
def settings_p():
    table_2_res = []
    try:
        sessionkey = request.cookies.get('dada')
        db_conn = psycopg2.connect(dbcon)
        sessionkey = validSession(db_conn, sessionkey)
        if sessionkey:
            s_table = []
            payload = []
            q_table = []
            data = {}
            data["heading"] = "LOCATION NAME"
            conn = psycopg2.connect(dbcon)
            cur = conn.cursor()
            cur.execute("""select u.cid,u.groups,ud.role_type,ud.full_name,ud.flag from ucgm as u join 
                                    user_details ud on u.user_id = ud.user_id where  ud.session_id = '"""+str(sessionkey)+"""'""")
            res = cur.fetchall()
            for r in res:
                cid = r[0]
                role_type = r[2]
                full_name = r[3]
                flag = r[4]
                allgroups = []

                if request.method == 'POST':        
                    group_id = request.form['group_id']
                    cur.execute("select group_id from groups where cid in ('"+str(cid)+"') and group_id in ('"+str(group_id)+"')")
                    res2 = cur.fetchall()
                    if len(res2) == 0:
                        allgroups.append(0)
                        allgroups.append(0)
                    else:
                        for r2 in res2:
                            allgroups.append(str(r2[0]))
                            allgroups.append(0)
                else:
                    if r[1] == 'all':
                        cur.execute("select group_id from groups where cid in ('"+str(cid)+"')")
                        res2 = cur.fetchall()
                        if len(res2) == 0:
                            allgroups.append(0)
                            allgroups.append(0)
                        else:
                            for r2 in res2:
                                allgroups.append(str(r2[0]))
                                allgroups.append(0)   
                    else:
                        b = (res[0][1]).split(',')
                        for c in b:
                            allgroups.append(c)
                            allgroups.append(0)   
                cur.execute("""  select d.uid,d.address,d.group_id,g.group_name,d.cid,c.customer_name,
                                    l.power_on,l.run,l.stop,l.alarm,l.pause,l.emergency,l.picesmade,l.current_consumption_kw,l.alarm_mach,l.lat,l.lng,l.lastupdate,l.program_number,
                                    d.machine_name,CASE when l.lastupdate is not null then 'Connected' else 'Not Connected' END,d.token,d.city,d.country,d.state,d.machine_info,
                                    l.run_action, l.stop_action,l.pause_action,
                                    l.program_number,l.program_name,l.length,l.height,l.corner,l.offsetx,l.offsety,l.offsetcorner,l.widthead,l.widthshoulders,l.lenghtshoulders,
                                    l.widthfeet,l.widthfeet2,l.lengthfeet,l.typecover,l.waiting_dt,l.waiting_time,l.real_dt,l.real_time,d.protocol_communication,d.ipaddress,d.port
                                    from devices d join customer_details c on d.cid=c.cid join groups g on d.group_id=g.group_id
                                    left join live_data l on cast (l.idmach as varchar) =d.uid
                                    join ucgm uc on d.cid =uc.cid join user_details u on uc.user_id = u.user_id where u.session_id = '"""+str(sessionkey)+"""'
                                    and d.group_id in """+str(tuple(allgroups))+""" order by 1""")
                results = cur.fetchall()

                if len(results) > 0:

                    cur.execute("""  select 
                                        program_number,program_name,length,height,corner,offsetx,offsety,offsetcorner,widthead,widthshoulders,lenghtshoulders,widthfeet,widthfeet2,lengthfeet,typecover,waiting_dt,waiting_time,real_dt,real_time,picesmade
                                        from live_data_log_view where idmach = '"""+str(results[0][0])+"""' group by program_number,program_name,length,height,corner,offsetx,offsety,offsetcorner,widthead,widthshoulders,lenghtshoulders,widthfeet,widthfeet2,
                                        lengthfeet,typecover,waiting_dt,waiting_time,real_dt,real_time,picesmade""" )

                    
                    programs = cur.fetchall()

                    cur.execute("select program_number,sum(daily_pices),DATE(lastupdate) from daily_pices_log where idmach = '"+str(results[0][0])+"' GROUP BY program_number,DATE(lastupdate) ")

                    daily_pices_res = cur.fetchall()
                    cur.execute("""SELECT
                                        dp.sum_daily_pices,
                                        COALESCE(ldl.sum_waiting_time, 0) AS sum_waiting_time,
                                        COALESCE(ldl.sum_real_time, 0) AS sum_real_time,
                                        dp.start_time,
                                        dp.end_time,
                                        dp.date_lastupdate
                                    FROM
                                        (SELECT
                                            SUM(daily_pices) AS sum_daily_pices,
                                            DATE(lastupdate) AS date_lastupdate,
                                            TO_CHAR(MIN(lastupdate), 'HH24:MI:SS') AS start_time,
                                            TO_CHAR(MAX(lastupdate), 'HH24:MI:SS') AS end_time
                                        FROM
                                            daily_pices_log
                                        GROUP BY
                                            DATE(lastupdate)) dp
                                    LEFT JOIN
                                        (SELECT
                                            SUM(waiting_time) AS sum_waiting_time,
                                            SUM(real_time) AS sum_real_time,
                                            DATE(lastupdate) AS date_lastupdate
                                        FROM
                                            live_data_log_view
                                        GROUP BY
                                            DATE(lastupdate)) ldl
                                    ON
                                        dp.date_lastupdate = ldl.date_lastupdate
                                    ORDER BY
                                        dp.date_lastupdate;""")
                    table_2 = cur.fetchall()

                cur.execute(""" select user_id,username,city,state,country,colorname,bg_color from user_details where session_id = '"""+str(sessionkey)+"""'""")
                results2 = cur.fetchall()

                colorname = "primary"
                useraddr = "Italy"
                bg_color = "dark"

                for result2 in results2:
                    username = str(result2[1])
                    useraddr = str(result2[2])+","+str(result2[3])+","+str(result2[4])
                    user_c_id = str(result2[0])

                    if str(result2[5]) in ['primary','blue','green','orange','red']:
                        colorname = str(result2[5])
                    if str(result2[6]) in ['dark','light']:
                        bg_color = str(result2[6])


                grp_l = {}


                cur.execute("select group_id,group_name from groups where cid ='"+str(cid)+"' ")

                grpd = cur.fetchall()

                for g in grpd:
                    if str(g[0]) not in grp_l:
                        grp_l[str(g[0])]=str(g[1])

                p_table = []

                total_waiting_time = 0
                total_real_time = 0
                if len(results) > 0:
                    for j in programs:
                        if j[16] != None:
                            total_waiting_time+=j[16]
                        if j[18] != None:
                            total_real_time += j[18]
                        p_table.append({
                            'program_number':str(j[0]) if str(j[0]) != 'None' else '-',
                            'program_name':str(j[1]) if str(j[1]) != 'None' else '-',
                            'length':str(j[2]) if str(j[2]) != 'None' else '-',
                            'height':str(j[3]) if str(j[3]) != 'None' else '-',
                            'corner':str(j[4]) if str(j[4]) != 'None' else '-',
                            'offsetx':str(j[5]) if str(j[5]) != 'None' else '-',
                            'offsety':str(j[6]) if str(j[6]) != 'None' else '-',
                            'offsetcorner':str(j[7]) if str(j[7]) != 'None' else '-',
                            'widthead':str(j[8]) if str(j[8]) != 'None' else '-',
                            'widthshoulders':str(j[9]) if str(j[9]) != 'None' else '-',
                            'lenghtshoulders':str(j[10]) if str(j[10]) != 'None' else '-',
                            'widthfeet':str(j[11])[:19] if str(j[11]) != 'None' else '-',
                            'widthfeet2':str(j[12]) if str(j[12]) != 'None' else '-',
                            'lengthfeet':str(j[13]) if str(j[13]) != 'None' else '-',
                            'typecover':str(j[14]) if str(j[14]) != 'None' else '-',
                            'waiting_dt':str(j[15])[:19] if str(j[15]) != 'None' else '-',
                            'waiting_time':str(j[16]) if str(j[16]) != 'None' else '-',
                            'real_dt':str(j[17])[:19] if str(j[17]) != 'None' else '-',
                            'real_time':str(j[18]) if str(j[18]) != 'None' else '-',
                            'picesmade':str(j[19]) if str(j[19]) != 'None' else '-'
                            
                            })
                    i = 0   
                    for result in results:
                        i += 1          
                        s_table.append(
                            {'sno':str(i),
                            'uid':str(result[0]),
                            'address':str(result[1]) if str(result[1]) != 'None' else '-',
                            'group_id':str(result[2]) if str(result[2]) != 'None' else '-',
                            'group_name':str(result[3]) if str(result[3]) != 'None' else '-',
                            'cid':str(result[4]) if str(result[4]) != 'None' else '-',
                            'customer_name':str(result[5]) if str(result[5]) != 'None' else '-',
                            'power_on': str(result[6]) if str(result[6]) != 'None' else '-',
                            'run': str(result[7]) if str(result[7]) != 'None' else '-',
                            'stop': str(result[8]) if str(result[8]) != 'None' else '-',
                            'alarm': str(result[9]) if str(result[9]) != 'None' else '-',
                            'pause': str(result[10]) if str(result[10]) != 'None' else '-',
                            'emergency': str(result[11]) if str(result[11]) != 'None' else '-',
                            'picesmade': str(result[12]) if str(result[12]) != 'None' else '-',
                            'current_consumption_kw': str(result[13]) if str(result[13]) != 'None' else '-',
                            'alarm_mach': str(result[14]) if str(result[14]) != 'None' else '-',
                            'lat': str(result[15]) if str(result[15]) != 'None' else '-',
                            'lng': str(result[16]) if str(result[16]) != 'None' else '-',
                            'lastupdate': str(result[17])[0:19] if str(result[17]) != 'None' else '-',
                            'task_number': str(result[18]) if str(result[18]) != 'None' else '-',
                            'machine_name':str(result[19]) if str(result[19]) != 'None' else '-',
                            'machine_connected':str(result[20]) if str(result[20]) != 'None' else '-',
                            'token':str(result[21]) if str(result[21]) != 'None' else '-',
                            'city':str(result[22]) if str(result[22]) != 'None' else '-',
                            'country':str(result[23]) if str(result[23]) != 'None' else '-',
                            'state':str(result[24]) if str(result[24]) != 'None' else '-',
                            'machine_info':str(result[25]) if str(result[25]) != 'None' else '-',
                            'run_action':str(result[26]) if str(result[26]) != 'None' else '-',
                            'stop_action':str(result[27]) if str(result[27]) != 'None' else '-',
                            'pause_action':str(result[28]) if str(result[28]) != 'None' else '-',				
                            'protocol_communication':str(result[48]) if str(result[48]) != 'None' else '-',
                            'ipaddress':str(result[49]) if str(result[49]) != 'None' else '-',
                            'port':str(result[50]) if str(result[50]) != 'None' else '-'
                                           
                            })  						

                    
                    for w in daily_pices_res:
                        q_table.append({
                            "program_number":str(w[0]),
                            "daily_pices":str(w[1]),
                            "lastupdate":str(w[2])
                            })

                    table_2_res = []
                    for l in table_2:
                        table_2_res.append({
                            "total_pices_made":str(l[0]),
                            "time_lost":str(round(l[1]/60,2))+" Hrs",
                            "time_real":str(round(l[2]/60,2))+" Hrs",
                            "start":str(l[3]),
                            "end":str(l[4]),
                            "date":str(l[5])
                            })

            cur.close()
            conn.close()

            donut_c = round((((total_waiting_time+total_real_time)- total_real_time)/ (total_waiting_time+total_real_time))*100,2) if (total_waiting_time+total_real_time) != 0 else 0

            return render_template("devices.html",table_2_res=table_2_res,flag=flag,total_waiting_time=round(total_waiting_time/60,2),total_real_time=round(total_real_time/60,2),total_time=round((total_waiting_time+total_real_time)/60,2),donut_c=donut_c, p_table=p_table,full_name=full_name, s_table=s_table,q_table=q_table, grp_l=grp_l, role_type=role_type, useraddr = useraddr,user_c_id=user_c_id,colorname=colorname, bg_color=bg_color)

        else:
            flash("session expired, Please try again...!")
            return redirect(url_for('logout'))
    except Exception as e:
        logger.exception(e)
        return render_template("page500.html")



@app.route("/notifications", methods=["GET","POST"])
def notifications_p():
    try:
        sessionkey = request.cookies.get('dada')
        db_conn = psycopg2.connect(dbcon)
        sessionkey = validSession(db_conn, sessionkey)
        if sessionkey:
            s_table = []
            payload = []
            data = {}
            data["heading"] = "LOCATION NAME"
            conn = psycopg2.connect(dbcon)
            cur = conn.cursor()
            cur.execute("""select u.cid,u.groups,ud.role_type,ud.full_name,ud.flag from ucgm as u join 
                                    user_details ud on u.user_id = ud.user_id where  ud.session_id = '"""+str(sessionkey)+"""'""")
            res = cur.fetchall()
            for r in res:
                cid = r[0]
                role_type = r[2]
                full_name=r[3]
                flag = r[4]
                allgroups = []

                if request.method == 'POST':         
                    group_id = request.form['group_id']
                    cur.execute("select group_id from groups where cid in ('"+str(cid)+"') and group_id in ('"+str(group_id)+"')")
                    res2 = cur.fetchall()
                    if len(res2) == 0:
                        allgroups.append(0)
                        allgroups.append(0)
                    else:
                        for r2 in res2:
                            allgroups.append(str(r2[0]))
                            allgroups.append(0)
                else:
                    if r[1] == 'all':
                        cur.execute("select group_id from groups where cid in ('"+str(cid)+"')")
                        res2 = cur.fetchall()
                        if len(res2) == 0:
                            allgroups.append(0)
                            allgroups.append(0)
                        else:
                            for r2 in res2:
                                allgroups.append(str(r2[0]))
                                allgroups.append(0)    
                    else:
                        b = (res[0][1]).split(',')
                        for c in b:
                            allgroups.append(c)
                            allgroups.append(0)   
                cur.execute("""  select idmach,notification_type,txt,lastupdate
                                    from notification""")
                results = cur.fetchall()
                cur.execute(""" select user_id,username,colorname,bg_color from user_details where session_id = '"""+str(sessionkey)+"""'""")
                results2 = cur.fetchall()

                colorname = "primary"
                bg_color = "dark"
                for result2 in results2:
                    username = str(result2[1])
                    user_c_id = str(result2[0])
                    if str(result2[2]) in ['primary','blue','green','orange','red']:
                        colorname = str(result2[2])

                    if str(result2[3]) in ['dark','light']:
                        bg_color = str(result2[3])


                grp_l = {}


                cur.execute("select group_id,group_name from groups where cid ='"+str(cid)+"' ")

                grpd = cur.fetchall()

                for g in grpd:
                    if str(g[0]) not in grp_l:
                        grp_l[str(g[0])]=str(g[1])


                i = 0   
                for result in results:
                    i += 1          
                    s_table.append(
                        {'sno':str(i),
                        'uid':str(result[0]),
                        'notification_type':str(result[1]),
                        'txt':str(result[2]),
                        'lastupdate':str(result[3])[0:19],
                        'duration':str(datetime.now()-result[3])[0:19]			

                                       
                        })      


            cur.close()
            conn.close()

            return render_template("notifications.html",flag=flag, full_name=full_name, s_table=s_table, grp_l=grp_l, role_type=role_type,user_c_id=user_c_id,colorname=colorname,bg_color=bg_color)

        else:
            flash("session expired, Please try again...!")
            return redirect(url_for('logout'))
    except Exception as e:
        logger.exception(e)
        return render_template("page500.html")
    


@app.route("/profile_view", methods=["GET","POST"])
def profile_view():
    try:
        sessionkey = request.cookies.get('dada')
        db_conn = psycopg2.connect(dbcon)
        sessionkey = validSession(db_conn, sessionkey)
        if sessionkey:
            data = {}
            user_id = ""
            username = ""
            phone_number = ""
            email_id = ""
            role_type = ""
            city = ""
            state = ""
            country = ""
            full_name = ""
            data["heading"] = "LOCATION NAME"
            conn = psycopg2.connect(dbcon)
            cur = conn.cursor()
            
            cur.execute(""" select user_id,username,phone_number,email_id,role_type,city,state,country,full_name,colorname,bg_color,flag from user_details where session_id = '"""+str(sessionkey)+"""'""")
            results = cur.fetchall()
            colorname = "primary"
            bg_color = "dark"
            for r in results:
                user_id=str(r[0])
                username=str(r[1])
                phone_number=str(r[2])
                email_id=str(r[3])
                role_type=str(r[4])
                city=str(r[5])
                state=str(r[6])
                country=str(r[7])
                full_name=str(r[8])
                flag= r[11]

                if str(r[9]) in ['primary','blue','green','orange','red']:
                    colorname = str(r[9])

                if str(r[10]) in ['dark','light']:
                    bg_color = str(r[10])                            
                       

            cur.close()
            conn.close()

            return render_template("profile.html",flag=flag,user_id=user_id,username=username,phone_number=phone_number,email_id=email_id,
                                    role_type=role_type,city=city,state=state,country=country,full_name=full_name, colorname=colorname, bg_color=bg_color, user_c_id=user_id) 
        else:
            flash("session expired, Please try again...!")
            return redirect(url_for('logout'))
    except Exception as e:
        logger.exception(e)
        return render_template("page500.html")



@app.route("/set_settings", methods=["GET","POST"])
def set_settings():
    try:
        sessionkey = request.cookies.get('dada')
        db_conn = psycopg2.connect(dbcon)
        sessionkey = validSession(db_conn, sessionkey)
        payload = []
        if sessionkey:
            if request.method == 'POST':
                settings_name = request.form.get('setting')
                if settings_name == 'edit_address':
                    uid = str(request.form.get('uid'))
                    machine_name =  str(request.form.get('machine_name'))
                    token =  str(request.form.get('token'))
                    city =  str(request.form.get('city'))
                    country =  str(request.form.get('country'))
                    state =  str(request.form.get('state'))
                    machine_info =  str(request.form.get('machine_info'))
                    protocol_comm =  str(request.form.get('protocol_comm'))
                    ipaddress =  str(request.form.get('ipaddress'))
                    port =  str(request.form.get('port'))

                

                    
                    try:
                        conn = psycopg2.connect(dbcon)
                        cur = conn.cursor()
                        cur.execute("""select d.uid
                                    from devices d join customer_details c on d.cid=c.cid
                                    join ucgm uc on d.cid =uc.cid join user_details u on uc.user_id = u.user_id where u.session_id = '"""+str(sessionkey)+"""'
                                     and d.uid = '"""+str(uid)+"""' order by 1""")
                        r = cur.fetchone()

                        if cur.rowcount == 1:
                            cur.execute("update devices set machine_name='"+machine_name+"', token='"+token+"', city='"+city+"', country='"+country+"', state='"+state+"', machine_info='"+machine_info+"', protocol_communication='"+protocol_comm+"', ipaddress='"+ipaddress+"', port='"+port+"' where uid = '"+uid+"'; ")
                            conn.commit()
                            cur.close()
                            conn.close()
                            return ("success")
                        else:
                            cur.close()
                            conn.close()
                            return (settings_name),400                      
                        
                        
                    except Exception as e:
                        logger.exception(e)
                        return (settings_name),400


                elif settings_name == 'deletemach':
                    try:
                        conn = psycopg2.connect(dbcon)
                        cur = conn.cursor()
                        cur.execute("delete from devices")
                        conn.commit()
                        cur.close()
                        conn.close()
                        return ("success")

                    except Exception as e:
                        logger.exception(e)
                        return (settings_name), 400	
                
                elif settings_name == 'action_newtask':
                    uid = str(request.form.get('uid'))
                    new_task_number =  str(request.form.get('new_task_number'))
                    
                    try:
                        conn = psycopg2.connect(dbcon)
                        cur = conn.cursor()
                        cur.execute("""select d.uid
                                    from devices d join customer_details c on d.cid=c.cid
                                    join ucgm uc on d.cid =uc.cid join user_details u on uc.user_id = u.user_id where u.session_id = '"""+str(sessionkey)+"""'
                                     and d.uid = '"""+str(uid)+"""' order by 1""")
                        r = cur.fetchone()

                        if cur.rowcount == 1:
                            cur.execute("update live_data set new_task_number='"+new_task_number+"' where idmach = '"+uid+"'; ")
                            conn.commit()
                            cur.close()
                            conn.close()
                            command = {"idmach":uid,"new_task_number":str(new_task_number)}
                            msgstr = json.dumps(command)
                            # mqtt_func(uid,msgstr)
                            return ("success")
                        else:
                            cur.close()
                            conn.close()
                            return (settings_name),400                      
                        
                        
                    except Exception as e:
                        logger.exception(e)
                        return (settings_name),400


                elif settings_name == 'action_run':
                    uid = str(request.form.get('uid'))
                    run_action =  str(request.form.get('run'))

                    if run_action=='0':
                        run_action = '1'
                    else:
                        run_action = '0'
                    

                    try:
                        conn = psycopg2.connect(dbcon)
                        cur = conn.cursor()
                        cur.execute("""select d.uid
                                    from devices d join customer_details c on d.cid=c.cid
                                    join ucgm uc on d.cid =uc.cid join user_details u on uc.user_id = u.user_id where u.session_id = '"""+str(sessionkey)+"""'
                                     and d.uid = '"""+str(uid)+"""' order by 1""")
                        r = cur.fetchone()

                        if cur.rowcount == 1:
                            cur.execute("update live_data set run_action='"+run_action+"' where idmach = '"+uid+"'; ")
                            conn.commit()
                            cur.close()
                            conn.close()
                            command = {"idmach":uid,"run_action":str(run_action)}
                            msgstr = json.dumps(command)
                            # mqtt_func(uid,msgstr)
                            return ("success")
                        else:
                            cur.close()
                            conn.close()
                            return (settings_name),400                      
                        
                        
                    except Exception as e:
                        logger.exception(e)
                        return (settings_name),400


                elif settings_name == 'action_stop':
                    uid = str(request.form.get('uid'))
                    stop_action =  str(request.form.get('stop'))
                    if stop_action=='0':
                        stop_action = '1'
                    else:
                        stop_action = '0'
                    
                    try:
                        conn = psycopg2.connect(dbcon)
                        cur = conn.cursor()
                        cur.execute("""select d.uid
                                    from devices d join customer_details c on d.cid=c.cid
                                    join ucgm uc on d.cid =uc.cid join user_details u on uc.user_id = u.user_id where u.session_id = '"""+str(sessionkey)+"""'
                                     and d.uid = '"""+str(uid)+"""' order by 1""")
                        r = cur.fetchone()

                        if cur.rowcount == 1:
                            cur.execute("update live_data set stop_action='"+stop_action+"' where idmach = '"+uid+"'; ")
                            conn.commit()
                            cur.close()
                            conn.close()
                            command = {"idmach":uid,"stop_action":str(stop_action)}
                            msgstr = json.dumps(command)
                            # mqtt_func(uid,msgstr)
                            return ("success")
                        else:
                            cur.close()
                            conn.close()
                            return (settings_name),400                      
                        
                        
                    except Exception as e:
                        logger.exception(e)
                        return (settings_name),400


                elif settings_name == 'action_pause':
                    uid = str(request.form.get('uid'))
                    pause_action =  str(request.form.get('pause'))
                    if pause_action=='0':
                        pause_action = '1'
                    else:
                        pause_action = '0'
                    
                    try:
                        conn = psycopg2.connect(dbcon)
                        cur = conn.cursor()
                        cur.execute("""select d.uid
                                    from devices d join customer_details c on d.cid=c.cid
                                    join ucgm uc on d.cid =uc.cid join user_details u on uc.user_id = u.user_id where u.session_id = '"""+str(sessionkey)+"""'
                                     and d.uid = '"""+str(uid)+"""' order by 1""")
                        r = cur.fetchone()

                        if cur.rowcount == 1:
                            cur.execute("update live_data set pause_action='"+pause_action+"' where idmach = '"+uid+"'; ")
                            conn.commit()
                            cur.close()
                            conn.close()
                            command = {"idmach":uid,"pause_action":str(pause_action)}
                            msgstr = json.dumps(command)
                            # mqtt_func(uid,msgstr)
                            return ("success")
                        else:
                            cur.close()
                            conn.close()
                            return (settings_name),400                      
                        
                        
                    except Exception as e:
                        logger.exception(e)
                        return (settings_name),400


                

                
                elif settings_name == 'edit_user':
                    user_id = str(request.form.get('user_id'))
                    flag = str(request.form.get('flag'))
                    
                    
                    try:
                        conn = psycopg2.connect(dbcon)
                        cur = conn.cursor()
                        cur.execute("update user_details set flag='"+flag+"' where user_id = '"+user_id+"'; ")
                        conn.commit()
                        cur.close()
                        conn.close()
                        return ("success")
                                             
                        
                        
                    except Exception as e:
                        logger.exception(e)
                        return (settings_name),400


                elif settings_name == 'edit_profile':
                    user_id = str(request.form.get('user_id'))
                    city = str(request.form.get('city'))
                    state = str(request.form.get('state'))
                    country = str(request.form.get('country'))
                    fullname = str(request.form.get('fullname'))
                    
                    try:
                        conn = psycopg2.connect(dbcon)
                        cur = conn.cursor()
                        cur.execute("update user_details set city='"+city+"',state='"+state+"',country='"+country+"',full_name='"+fullname+"' where user_id = '"+user_id+"'; ")
                        conn.commit()
                        cur.close()
                        conn.close()
                        return ("success")
                                             
                        
                        
                    except Exception as e:
                        logger.exception(e)
                        return (settings_name),400


                elif settings_name == 'edit_pw':
                    user_id = str(request.form.get('user_id'))
                    current_pw = base64_enc(str(request.form.get('current_pw')))
                    new_pw = base64_enc(str(request.form.get('new_pw')))
                    
                    
                    try:
                        conn = psycopg2.connect(dbcon)
                        cur = conn.cursor()

                        cur.execute("select user_id from user_details where user_id = '"+str(user_id)+"' and password='"+str(current_pw)+"'")
                        r = cur.fetchone()


                        if cur.rowcount == 1:
                            cur.execute("update user_details set password='"+str(new_pw)+"' where user_id = '"+user_id+"'; ")
                            conn.commit()
                            cur.close()
                            conn.close()
                            return ("Password Updated Successfully")
                        else:
                            cur.close()
                            conn.close()
                            return ("Incorrect Password"),400
                                             
                        
                        
                    except Exception as e:
                        logger.exception(e)
                        return (settings_name),400



                elif settings_name == 'colorchange':
                    user_id = str(request.form.get('user_id'))
                    colorname = str(request.form.get('colorname'))
                    bg_color = str(request.form.get('bg_color'))

                    # print(user_id, colorname, file=sys.stderr)
                    
                    
                    try:
                        conn = psycopg2.connect(dbcon)
                        cur = conn.cursor()

                        cur.execute("select user_id from ucgm where cid in (select cid from ucgm where user_id = '"+str(user_id)+"')")
                        r = cur.fetchall()


                        if cur.rowcount > 1:

                            for e in r:
                                if colorname != 'None':
                                    cur.execute("update user_details set colorname='"+str(colorname)+"' where user_id = '"+str(e[0])+"'; ")
                                if bg_color != 'None':
                                    cur.execute("update user_details set bg_color='"+str(bg_color)+"' where user_id = '"+str(e[0])+"'; ")
                            conn.commit()
                            cur.close()
                            conn.close()
                            return ("success")
                        else:
                            cur.close()
                            conn.close()
                            return ("Error"),400
                                             
                        
                        
                    except Exception as e:
                        logger.exception(e)
                        return (settings_name),400


                

                elif settings_name == 'add_machine':
                    # print(request.form, file=sys.stderr)
                    uid = str(request.form.get('uid'))
                    machine_name =  str(request.form.get('machine_name'))
                    # token =  str(uuid.uuid4().hex)
                    token =  str(request.form.get('token'))
                    city =  str(request.form.get('city'))
                    country =  str(request.form.get('country'))
                    state =  str(request.form.get('state'))
                    machine_info =  str(request.form.get('machine_info'))
                    protocol_comm =  str(request.form.get('protocol_comm'))
                    ipaddress =  str(request.form.get('ipaddress'))
                    port =  str(request.form.get('port'))
                    
                    try:
                        conn = psycopg2.connect(dbcon)
                        cur = conn.cursor()
                        


                        cur.execute("""select g.cid,g.group_id
                        from groups g 
                        join ucgm uc on uc.groups = cast ( g.group_id as varchar) join user_details u on uc.user_id = u.user_id where u.session_id = '"""+str(sessionkey)+"""'""")

                        r = cur.fetchone()

                        if cur.rowcount == 1:
                            query_update = "update devices set group_id='"+str(r[1])+"',cid='"+str(r[0])+"',machine_name='"+str(machine_name)+"',token='"+str(token)+"',city='"+str(city)+"',country='"+str(country)+"',state='"+str(state)+"',machine_info='"+str(machine_info)+"' where uid ='"+str(uid)+"';"
                            
                            query_ins = "insert into devices (uid,group_id,cid,status,machine_name,token,city,country,state,machine_info,protocol_communication,ipaddress,port) "
                            query_ins += "select '"+str(uid)+"','"+str(r[1])+"','"+str(r[0])+"','"+str('active')+"','"+str(machine_name)+"','"+str(token)+"','"+str(city)+"','"+str(country)+"','"+str(state)+"','"+str(machine_info)+"','"+str(protocol_comm)+"','"+str(ipaddress)+"','"+str(port)+"' "
                            query_ins += " WHERE '"+str(uid)+"' not in (select uid from devices where uid='"+str(uid)+"')"

                            cur.execute(query_update)
                            cur.execute(query_ins)

                            conn.commit()
                            cur.close()
                            conn.close()
                            return ("success")
                        else:
                            cur.close()
                            conn.close()
                            return (settings_name),400                      
                        
                        
                    except Exception as e:
                        logger.exception(e)
                        return (settings_name),400


                elif settings_name == 'add_customer':
                    name = str(request.form.get('customer_name')).lower()
                    email = str(request.form.get('customer_email')).lower()
                    password = base64_enc(str(request.form.get('customer_password')))
                    phone = str(request.form.get('customer_phone'))
                    city = str(request.form.get('customer_city')).lower()
                    state = str(request.form.get('customer_state')).lower()
                    country = str(request.form.get('customer_country')).lower()

                    if(re.fullmatch(regex, email)) == None:
                        return ('Invalid Email'),400

                    try:
                        isinstance(int(phone), int)
                    except:
                        return ("Invalid Phonenumber"),400

                    
                    try:
                        conn = psycopg2.connect(dbcon)
                        cur = conn.cursor()
                        cur.execute("""select cid from customer_details where customer_name = '"""+name+"""' or email_id = '"""+email+"""' or phone_number ='"""+phone+"""'""")
                        r = cur.fetchall()


                        if cur.rowcount != 0:
                            return ("Entered details already exist"),400


                        cur.execute("""select user_id from user_details where email_id = '"""+email+"""' or phone_number ='"""+phone+"""'""")
                        b = cur.fetchall()
                        if cur.rowcount != 0:
                            return ("Entered details already exist"),400
                        
                        else:
                            cur.execute("insert into customer_details (customer_name,email_id,phone_number,city,state,country,status,lastupdate) values('"+name+"','"+email+"','"+phone+"','"+city+"','"+state+"','"+country+"','active',now()) returning cid;")
                            r = cur.fetchone()

                            # print(r[0],"customer id", file=sys.stderr)


                            qry = "insert into user_details (username,phone_number,email_id,role_type,status,city,state,country,full_name,password) values( "
                            qry += "'"+name+"','"+str(phone)+"','"+email+"','customer_admin','active','"+city+"','"+state+"','"+country+"','"+name+"','"+password+"') returning user_id;"
                            cur.execute(qry)
                            h = cur.fetchone()
                            conn.commit()
                            cur.close()
                            conn.close()


                            # print(h[0], 'user_id', file=sys.stderr)
                            conn = psycopg2.connect(dbcon)
                            cur = conn.cursor()
                            cur.execute("INSERT INTO groups(group_name, cid) VALUES ('"+str(name)+"','"+str(r[0])+"');")
                            cur.execute("insert into ucgm (user_id,cid,groups) values('"+str(h[0])+"','"+str(r[0])+"','all');")
                            conn.commit()
                            cur.close()
                            conn.close()
                            return ("success")
                                              
                        
                        
                    except Exception as e:
                        logger.exception(e)
                        return (settings_name),400


                elif settings_name == 'add_user':
                    fullname = str(request.form.get('fullname')).lower()
                    email_id = str(request.form.get('email_id')).lower()
                    phone_number = str(request.form.get('phone_number'))
                    city = str(request.form.get('city')).lower()
                    state = str(request.form.get('state')).lower()
                    country = str(request.form.get('country')).lower()
                    cid = str(request.form.get('cid'))
                    password = base64_enc(str(request.form.get('password')))
                    flag = (str(request.form.get('flag')))

                    if(re.fullmatch(regex, email_id)) == None:
                        return ('Invalid Email'),400

                    try:
                        isinstance(int(phone_number), int)
                    except:
                        return ("Invalid Phonenumber"),400

                    
                    try:
                        conn = psycopg2.connect(dbcon)
                        cur = conn.cursor()
                        cur.execute("""select user_id from user_details where email_id = '"""+email_id+"""'""")
                        r = cur.fetchall()


                        if cur.rowcount != 0:
                            return ("Entered Email_id or Phone number already exist"),400
                        else:
                            qry = "insert into user_details (username,phone_number,email_id,role_type,status,city,state,country,full_name,password,flag) values( "
                            qry += "'"+fullname+"','"+str(phone_number)+"','"+email_id+"','user_admin','active','"+city+"','"+state+"','"+country+"','"+fullname+"','"+password+"','"+flag+"') returning user_id;"
                            cur.execute(qry)
                            r = cur.fetchone()
                            conn.commit()
                            cur.close()
                            conn.close()

                            # print(r[0], "user_id", file=sys.stderr)

                            conn = psycopg2.connect(dbcon)
                            cur = conn.cursor()
                            cur.execute("INSERT INTO groups(group_name, cid) VALUES ('default','"+str(cid)+"') returning group_id;")
                            g = cur.fetchone()
                            conn.commit()
                            cur.close()
                            conn.close()

                            # print(g[0], "group_id", file=sys.stderr)

                            conn = psycopg2.connect(dbcon)
                            cur = conn.cursor()
                            cur.execute("insert into ucgm (user_id,cid,groups) values('"+str(r[0])+"','"+str(cid)+"','"+str(g[0])+"');")
                            conn.commit()
                            cur.close()
                            conn.close()
                            return ("success")
                                              
                        
                        
                    except Exception as e:
                        logger.exception(e)
                        return (settings_name),400


                
            else:
                return render_template("page500.html")
        else:
            flash("session expired, Please try again...!")
            return redirect(url_for('logout'))
    except Exception as e:
        logger.exception(e)
        return render_template("page500.html")


@app.route('/create_admin',methods=['GET','POST'])
def create_customer():
    if request.method == 'GET':
        return render_template("create_customer.html")

    name = str(request.form.get('customer_name')).lower()
    email = str(request.form.get('customer_email')).lower()
    password = base64_enc(str(request.form.get('customer_password')))
    phone = '000'
    city, state, country = 'city', 'state', 'country'

    if not re.fullmatch(regex, email):
        flash("Invalid Email Id, Please try again..!")
        return redirect(url_for('create_customer'))

    try:
        phone_as_int = int(phone)
    except ValueError:
        flash("Invalid Phone Number, Please try again..!")
        return redirect(url_for('create_customer'))

    try:
        with psycopg2.connect(dbcon) as conn:
            with conn.cursor() as cur:
                # Inserimento in customer_details e ottenere CID
                cur.execute(
                    """
                    INSERT INTO customer_details
                    (customer_name, email_id, phone_number, city, state, country, status, lastupdate)
                    VALUES (%s, %s, %s, %s, %s, %s, 'active', NOW())
                    RETURNING cid;
                    """,
                    (name, email, phone, city, state, country)
                )
                r = cur.fetchone()

                if r is None:
                    raise ValueError("Failed to insert customer_details. CID not returned.")

                cid = r[0]  # Il valore di CID generato

                # Inserimento in user_details usando lo stesso CID come user_id
                cur.execute(
                    """
                    INSERT INTO user_details
                    (user_id, username, phone_number, email_id, role_type, status, city, state, country, full_name, password)
                    VALUES (%s, %s, %s, %s, 'super_admin', 'active', %s, %s, %s, %s, %s); 
                    """,
                    (cid, name, phone, email, city, state, country, name, password)
                )

                # Inserimento in groups
                cur.execute(
                    "INSERT INTO groups (group_name, cid) VALUES (%s, %s);",
                    (name, cid)
                )

                # Inserimento in ucgm
                cur.execute(
                    "INSERT INTO ucgm (user_id, cid, groups) VALUES (%s, %s, 'all');",
                    (cid, cid)
                )

            conn.commit()

        return render_template("user-login.html", info="Admin created, Please Login..!")

    except Exception as e:
        logger.exception("An error occurred while creating the customer.")
        flash("An unexpected error occurred. Please try again later.")
        return redirect(url_for('create_customer'))

# Bot Ai 
# Configura Botpress
BOT_ID = "iic_bot"  # Modifica con il tuo ID Bot
BOT_BASE_URL = "http://localhost:3000/api/v1/bots"

def get_user_id(sessionkey):
    """Recupera l'ID dell'utente dalla sessione attiva."""
    print ("to get user")
    try:
        if not sessionkey:
            flash("Session expired, please try again.")
            return None

        with psycopg2.connect(dbcon) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                SELECT u.cid
                FROM ucgm u 
                JOIN user_details ud ON u.user_id = ud.user_id 
                WHERE ud.session_id = %s
                """, (sessionkey,))
                user = cur.fetchone()
                logger.info(f"User ID {user[0]} retrieved successfully.")

        return user[0] if user else None
    except Exception as e:
        logger.exception("Error whiling NOT find user Id for BOT.")
        return None


@app.route('/chatbot', methods=['POST'])
def chatbot():
    """Comunica con il chatbot di Botpress e interroga il database in base all'intent."""
    try:
        print("chatbot starting")
        # Recupera la sessione dell'utente dal cookie
        sessionkey = request.cookies.get('dada')
        if not sessionkey:
            return jsonify({'error': 'Utente non autenticato'}), 403
            print("sessionkey not found")
        else:
            print("sessionkey found")
        db_conn = psycopg2.connect(dbcon)
        sessionkey = validSession(db_conn, sessionkey)
        print ("sessionkey validate is: ", sessionkey)
        
        
        data = request.get_json()
        print ("data is: ", data)
        user_message = data.get('message')
        print(f"📩 Messaggio utente: {user_message}", file=sys.stderr)

        # Recupera l'ID utente dal database
        user_id = get_user_id(sessionkey)
        if not user_id:
            return jsonify({'error': 'Utente non autenticato'}), 403  # Forbidden
        
        # Chiamata a Botpress per ottenere l'intent
        bot_url = f"{BOT_BASE_URL}/{BOT_ID}/converse/{user_id}"
        print(f"🤖 Bot agent IIC URL: {bot_url}", file=sys.stderr)

        response = requests.post(bot_url, json={"type": "text", "text": user_message})
        if response.status_code != 200:
            return jsonify({'error': 'Errore nella comunicazione con il chatbot'}), 500

        # Analizza la risposta di Botpress
        bot_response = response.json().get('responses', [])
        if not bot_response:
            return jsonify({'error': 'Nessuna risposta dal bot'}), 500

        intent = bot_response[0].get('text', '').strip().lower()
        print(f"🎯 Intent riconosciuto: {intent}", file=sys.stderr)

        # Connessione al database per ottenere i dati
        conn = db_conn
        cur = conn.cursor()

        # Mappatura intent -> Query al database
        if intent == "dammi_produzione":
            cur.execute("SELECT SUM(production_count) FROM production_data")
            produzione_totale = cur.fetchone()[0] or 0
            response_text = f"La produzione totale è di {produzione_totale} unità."

        elif intent == "produzione_giornaliera":
            cur.execute("SELECT SUM(production_count) FROM production_data WHERE date = CURRENT_DATE")
            produzione_oggi = cur.fetchone()[0] or 0
            response_text = f"Oggi la produzione è di {produzione_oggi} unità."

        elif intent == "produzione_periodo":
            cur.execute("SELECT SUM(production_count) FROM production_data WHERE date >= CURRENT_DATE - INTERVAL '3 months'")
            produzione_3_mesi = cur.fetchone()[0] or 0
            cur.execute("SELECT SUM(production_count) FROM production_data WHERE date >= CURRENT_DATE - INTERVAL '6 months'")
            produzione_6_mesi = cur.fetchone()[0] or 0
            response_text = f"Negli ultimi 3 mesi: {produzione_3_mesi} unità. Negli ultimi 6 mesi: {produzione_6_mesi} unità."

        elif intent == "percentuali_macchina":
            cur.execute("""
                SELECT 
                    SUM(run_time) AS run, 
                    SUM(stop_time) AS stop, 
                    SUM(emergency_time) AS emergency
                FROM machine_status
            """)
            run, stop, emergency = cur.fetchone()
            response_text = f"Percentuale operativa: Run {run}%, Stop {stop}%, Emergency {emergency}%."

        elif intent == "report_dettagliato":
            response_text = "Per generare un report dettagliato, visita la sezione 'Report' della dashboard."

        elif intent is not None:
            response_text= intent

        else:
            response_text = "Non ho capito la richiesta. Puoi riformularla?"

        # Chiudi connessione al database
        cur.close()
        conn.close()

        # Invia risposta al frontend
        return jsonify({'messages': [response_text]})

    except Exception as e:
        print(f"❌ Errore chatbot: {str(e)}", file=sys.stderr)
        return jsonify({'error': 'Errore interno del server'}), 500


def open_browser():
    webbrowser.open_new("http://127.0.0.1:5000")

if __name__ ==  "__main__":
    #Timer(3, open_browser).start()
    #app.run(host='0.0.0.0',port=5000,debug=True)
    app.run(debug=True)
    #webview.start()