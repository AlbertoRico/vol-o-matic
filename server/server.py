import os, sys, traceback
import time
import json
import zipfile
import glob
import smtplib
import yaml

from flask import Flask, request
from werkzeug import secure_filename

import volatility_interface
import decision_tree
import deciders
import signatures

UPLOAD_FOLDER = './tmp/'
ALLOWED_EXTENSIONS = set(['zip'])
THRESHOLD = 0.5
WORKLIST = ["processes", "connections", "devices", "rootkits"]
EMAIL_LIST = ["example@example.com"]

def main():
    worklist = WORKLIST
    image_file = "file://../client/DTU-5A40BFDB6E6-20150311-235213.raw"
    signatures_dictionary = signatures.dictionary

    #analyze_image(image_file, worklist, signatures_dictionary)

    load_config()
    setup_server()
    return

def load_config():
    with open("config.json") as config_json:
        config = yaml.safe_load(config_json)

        WORKLIST = config.get("worklist")
        EMAIL_LIST = config.get("email")

def analyze_image(image_file, worklist, signatures):
    start_time = time.time()
    print "Started analysis."
    analyzer = volatility_interface.Analyzer(image_file)
    decider_list = load_deciders_from_worklist(worklist)

    runner = decision_tree.Runner(analyzer, signatures, decider_list, THRESHOLD)


    results = runner.run()

    total_time = time.time() - start_time
    print "Analysis concluded - Time: " + str(total_time) + "seconds"

    return results


def load_deciders_from_worklist(worklist):
    loaded_deciders = []

    for decider_name in worklist:
        d = getattr(deciders, decider_name)
        loaded_deciders.append(d.load_decider())

    return loaded_deciders


def setup_server():
    http_server = Flask(__name__)
    http_server.debug = True
    http_server.threaded = True
    http_server.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

    @http_server.route('/upload', methods=['GET', 'POST'])
    def upload_file():
        if request.method == 'POST':
            file = request.files['file']
            if file and allowed_file(file.filename):
                # Save posted .zip file
                filename = secure_filename(file.filename)

                compressed_file_path = os.path.join(http_server.config['UPLOAD_FOLDER'],
                          filename)

                file.save(compressed_file_path)

                # Uncompress content of zip file
                tmp_zip_dir = compressed_file_path+"_contents/"
                os.mkdir(tmp_zip_dir)
                unzip(compressed_file_path, tmp_zip_dir)

                # Analyze included image file (assumed one raw image)
                tmp_raw_files = glob.glob(tmp_zip_dir+'*.raw')
                tmp_raw_path = "file://" + tmp_raw_files[0]

                decision = analyze_image(tmp_raw_path, WORKLIST, signatures.dictionary)

                try:
                    send_email(decision, request.remote_addr)
                except BaseException:
                    print "Notification error - Check that the SMTP server is configured properly"
                    print decision



                return json.dumps(
                    {
                        "status": "ok"
                    }
                )
            return json.dumps(
                {
                    "status": "error",
                    "message": "No dump file supplied."
                }
            )

    http_server.run(host='0.0.0.0')

def send_email(decision, ip):
    subject = "Breach report - " + ip

    smtp_server = "localhost"

    from_address = "iocrunner@example.com"
    to_address = EMAIL_LIST # must be a list

    content = """
    -Breach report-

    %s
    """ %(decision)

    # Prepare actual message

    message = """\
    From: %s
    To: %s
    Subject: %s

    %s
    """ % (from_address, ", ".join(to_address), subject, content)

    # Send the mail

    server = smtplib.SMTP(smtp_server)
    server.sendmail(from_address, to_address, message)
    server.quit()

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

# Secure solution from http://stackoverflow.com/q/12886768
# Avoids path traversal
def unzip(source_filename, dest_dir):
    start_time = time.time()
    print "Started decompression."

    with zipfile.ZipFile(source_filename) as zf:
        for member in zf.infolist():
            words = member.filename.split('/')
            path = dest_dir
            for word in words[:-1]:
                drive, word = os.path.splitdrive(word)
                head, word = os.path.split(word)
                if word in (os.curdir, os.pardir, ''): continue
                path = os.path.join(path, word)
            zf.extract(member, path)

    total_time = time.time() - start_time
    print "Decompression successful - Time: " + str(total_time) + "seconds"



if __name__ == "__main__":
    main()
