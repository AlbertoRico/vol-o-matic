'Main procedure
Function Main()
  'compress dump file
  'ArchiveFolder "DTU-5A40BFDB6E6-20150311-235213.raw", "tmp_dump.zip"

  'send file to analysis server
  Wscript.Echo WinHTTPPostRequest("http://192.168.10.1:5000/upload", "tmp_dump.zip")
End Function

Sub ArchiveFolder (SourceFile, ZipFile)

    With CreateObject("Scripting.FileSystemObject")
        ZipFile = .GetAbsolutePathName(ZipFile)
        SourceFile = .GetAbsolutePathName(SourceFile)

        With .CreateTextFile(ZipFile, True)
            .Write Chr(80) & Chr(75) & Chr(5) & Chr(6) & String(18, chr(0))
        End With
    End With

    With CreateObject("Shell.Application")
        .NameSpace(ZipFile).CopyHere .NameSpace(SourceFile)
    End With

End Sub

'sends multipart/form-data To the URL using WinHttprequest/XMLHTTP
'FormData - binary (VT_UI1 | VT_ARRAY) multipart form data
Function WinHTTPPostRequest(URL, File)
  Set HTTP = WScript.CreateObject("Microsoft.XMLHTTP")
  Set fso = CreateObject("Scripting.FileSystemObject")

  Set objStream = CreateObject("ADODB.Stream")
  objStream.Type = 1
  objStream.Open 
  objStream.LoadFromFile(fso.GetFileName(File))

  HTTP.open "POST", URL, False 
  
  HTTP.send objStream.Read

  WinHTTPPostRequest = HTTP.responseText
End Function

'Run main procedure
Main()
