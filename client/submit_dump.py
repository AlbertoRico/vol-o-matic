import zipfile
import datetime
import poster
import urllib2
import sys

TMP_FOLDER = "./tmp/"
FILE_PREFIX = "DTU_IoC_"


def main():
    if (len(sys.argv) < 5):
        print "Memory image submission tool"
        print "Usage: python " + sys.argv[0] + " -f <imageFile> -d <url>"
        return

    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    zipDstPath = TMP_FOLDER + FILE_PREFIX + timestamp + ".zip"

    dumpPath = sys.argv[2]
    dstUrl   = sys.argv[4]

    print "Compressing dump file..."
    compressFile(dumpPath, zipDstPath)

    print "Submitting file for analysis..."
    submitFile(zipDstPath, dstUrl)

    print "Done."

    return


def submitFile(filePath, url):
    poster.streaminghttp.register_openers()

    datagen, headers = poster.encode.multipart_encode(
        {
            "file": open(filePath, "rb")
        }
    )

    # Create the Request object
    request = urllib2.Request("http://localhost:5000/upload",
                              datagen,
                              headers)

    # Actually do the request, and get the response
    urllib2.urlopen(request).read()

    return


def compressFile(filePath, dstPath):
    """ Compresses a file in ZIP """

    zf = zipfile.ZipFile(dstPath, mode='w')

    try:
        zf.write(filePath)
    finally:
        zf.close()
    return


if __name__ == "__main__":
    main()
