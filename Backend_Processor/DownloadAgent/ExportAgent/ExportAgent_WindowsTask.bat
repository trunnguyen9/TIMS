python C:\Users\Trung\PycharmProjects\TIMS\Backend_Processor\DownloadAgent\ExportAgent\ExportSQL.py >> ..\EA_errors.txt
del ..\Exports\* /F /Q
move *.csv ..\Exports
move *.txt ..\Exports
move *.bro ..\Exports
move *.snort ..\Exports
move *.json ..\Exports
