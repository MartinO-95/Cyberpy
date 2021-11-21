#Author: Martin O'Connor
#Date: 11/05/2021
#Purpose: To provide a graphical interface for the nslookup command and to quickly access notepad with gathered information
#-------------------------------------------------------------------------------------------------------------------------------------------

#Imported modules---------------------------------------------------------------------------------------------------------------------------
#System modules
import os
import webbrowser
#tkinter graphical user interface modules:
from tkinter import * 
from tkinter import filedialog 
from tkinter import simpledialog 
from tkinter import messagebox  
from tkinter.ttk import *
from tkinter import Scrollbar
from tkinter.scrolledtext import ScrolledText
#Other modules
from datetime import datetime
#-------------------------------------------------------------------------------------------------------------------------------------------

#global variables---------------------------------------------------------------------------------------------------------------------------
global name 
global name2
#-------------------------------------------------------------------------------------------------------------------------------------------

#Defintions for program functions-----------------------------------------------------------------------------------------------------------
#---File option definitions---
#Open a textfile in a specific folder using a built in file dialog window.
def onOpen(): 
    name=filedialog.askopenfilename(initialdir = "/",title = "Open file",filetypes = (("Python files","*.py;*.pyw"),("All files","*.*")))
    if name != "": # picks up on the cancel key
       os.popen("notepad "+name) # uses notepad to open a textfile, for editing and no command line window to be shown
#Save a textfile from notepad
def onSave():
    name=filedialog.askopenfilename(initialdir = "/",title = "Open file",filetypes = (("Python files","*.py;*.pyw"),("All files","*.*")))
    if name != "": # picks up on the cancel key
       name2=os.path.abspath(name) # finds the all of the path to the file entered
       os.popen("notepad "+name2) # opens the file and allows it to save it.

#---Built in notepad definitions---
#New notepad page
def cmdNew():     #file menu New option
    global fileName
    if len(notepad.get('1.0', END+'-1c'))>0:
        if messagebox.askyesno("Notepad", "Do you want to save changes?"):
            cmdSave()
        else:
            notepad.delete(0.0, END)
    app.title("Notepad")
#Open a text file with the built in notepad        
def cmdOpen():     #file menu Open option
    fd = filedialog.askopenfile(parent = app, mode = 'r')
    t = fd.read()     #t is the text read through filedialog
    notepad.delete(0.0, END)
    notepad.insert(0.0, t)
#Save the results displayed on the built in notepad
def cmdSave():     
    fd = filedialog.asksaveasfile(mode = 'w', defaultextension = '.txt')
    if fd!= None:
        data = notepad.get('1.0', END)
    try:
        fd.write(data)
    except:
        messagebox.showerror(title="Error", message = "Not able to save file!")
#Save as option for the built in notepad
def cmdSaveAs():
    fd = filedialog.asksaveasfile(mode='w', defaultextension = '.txt')
    t = notepad.get(0.0, END)     #Using "t" will now get text from the notepad
    try:
        fd.write(t.rstrip())
    except:
        messagebox.showerror(title="Error", message = "Not able to save file!")

#---Notepad edit menu definitions---
#Copy selected text
def cmdCopy():     #edit menu Copy option
    notepad.event_generate("<<Copy>>")
#Cut selected text
def cmdCut():     #edit menu Cut option
    notepad.event_generate("<<Cut>>")
#Paste text from clipboard
def cmdPaste():     #edit menu Paste option
    notepad.event_generate("<<Paste>>")
#Select all text
def cmdSelectAll():     #edit menu Select All option
    notepad.event_generate("<<SelectAll>>")        
#Clear all text
def cmdClear():     #edit menu Clear option
    if messagebox.askyesno(title="Clear all text", message="Please save any results you wish to keep before clicking yes"):
        notepad.event_generate("<<Clear>>")
#Find text option
def cmdFind():
    notepad.tag_remove("Found",'1.0', END)
    find = simpledialog.askstring("Find", "Find what:")
    if find:
        idx = '1.0'     #idx = index
    while 1:
        idx = notepad.search(find, idx, nocase = 1, stopindex = END)
        if not idx:
            break
        lastidx = '%s+%dc' %(idx, len(find))
        notepad.tag_add('Found', idx, lastidx)
        idx = lastidx
    notepad.tag_config('Found', foreground = 'white', background = 'blue')
    notepad.bind("<1>", click)
#Handling a click event
def click(event):
    notepad.tag_config('Found',background='white',foreground='black') 

#---Utility definitions---
#Open notepad externally
def runnotepad():
    os.popen ("notepad.exe")
#Open system information
def runsysinf():
    sysinf=os.popen('msinfo32.exe')
#Open task manager
def runtasklist():
    tasklist=os.popen('taskmgr.exe')
#Open calculator
def runcalc():
    calc=os.popen('calc.exe')

#---Network test definitions---
#Address resolution protocol (ARP)
def runarp():
    arpd=""
    arpi=os.popen('arp -a')
    for arpo in arpi.readlines():
        arpd=arpd+arpo
    notepad.insert(0.0, str(arpd))
#Internet protocol (IP) configuration with all compartments
def runipconf():
    ipconfd=""
    ipconfi=os.popen('ipconfig -allcompartments -all')
    for ipconfo in ipconfi.readlines():
        ipconfd=ipconfd+ipconfo
    notepad.insert(0.0, str(ipconfd))     
#Ping function
def runping():
   pingd=""  
   pingi=simpledialog.askstring(title="Ping",prompt="Enter IP address:")
   if pingi is not None and pingi != "":
      pingo=os.popen("ping -n 4 "+pingi)
      #concatenate all ping results 
      for pingo in pingo.readlines():
          pingd=pingd+str(pingo)+"\n"
      notepad.insert(0.0, str(pingd))
   elif (pingi==""):                      # picks up if ipurl is blank
        messagebox.showinfo(title="Error", message="Error. Try again!")
#Traceroute/Tracert function
def runtraceroute():
    traced=""
    tracei=simpledialog.askstring(title="Traceroute",prompt="Enter IP or web URL")
    if tracei is not None and tracei != "":
       traceo=os.popen("tracert "+tracei)
       for traceo in traceo.readlines():
           traced=traced+str(traceo)+"\n"
       notepad.insert(0.0, str(traced)) 
    elif (tracei==""):
        messagebox.showinfo(title="Error", message="Error. Try again!")
#(D)NSlookup function
def runnslookup():
    nslookupd=""
    nslookupi=simpledialog.askstring(title="nslookup",prompt="Enter IP or web URL:")
    if nslookupi is not None and nslookupi != "":
        nslookupo=os.popen("nslookup "+nslookupi)
        for nslookupo in nslookupo.readlines():
            nslookupd=nslookupd+str(nslookupo)+"\n"
        notepad.insert(0.0, str(nslookupd))    
    elif (nslookupi==""):
        messagebox.showinfo(title="Error", message="Error. Try again!")
#Display the routing table
def runnetstat():
    netstatd=""
    netstati=os.popen('netstat -r')
    for netstato in netstati.readlines():
        netstatd=netstatd+netstato
    notepad.insert(0.0, str(netstatd))

#---Webtools---
#Open URLscan.io webpage
def openrurlscan():
    webbrowser.open_new("https://urlscan.io/")
#Open VirusTotal webpage
def openvirusscan():
    webbrowser.open_new("https://www.virustotal.com/gui/")
#Open CyberChef webpage
def opencyberchef():
    webbrowser.open_new('https://gchq.github.io/CyberChef/')
#What's my name search
def namesearch():
    namecriteria=simpledialog.askstring(title="Enter a username",prompt='Name')
    searchname='https://whatsmyname.app/?q='+namecriteria
    webbrowser.open_new(searchname)

#---Cyber security Frameworks---
#Open OSINTframework webpage
def openosint():
    webbrowser.open_new("https://osintframework.com/")
#Open Attack Mitre webpage
def openmitre():
    webbrowser.open_new("https://attack.mitre.org/")

#---Google dorks definitions---
#Search for URL's containing specified text
def runinurl():
    googlecriteria=simpledialog.askstring(title="Enter a key term you wish to search for on the internet",prompt='Search key in URL')
    searchgoogle="https://www.google.com/search?q=allinurl:"+googlecriteria
    webbrowser.open_new(searchgoogle)
def runintitle():
    googlecriteria=simpledialog.askstring(title="Enter a key term you wish to search for on the internet",prompt='Search key in Title')
    searchgoogle="https://www.google.com/search?q=allintitle:"+googlecriteria
    webbrowser.open_new(searchgoogle)
#Search for specified text
def runintext():
    googlecriteria=simpledialog.askstring(title="Enter a key term you wish to search for on the internet",prompt='Search key in Text')
    searchgoogle="https://www.google.com/search?q=allintext:"+googlecriteria
    webbrowser.open_new(searchgoogle)

#---Information definitions--- 
#Get help function
def gethelp():
    gethelpd=""
    gethelpi=simpledialog.askstring(title="Get help",prompt="Type the command you need help with: ")
    if gethelpi is not None and gethelpi != "":
        gethelpo=os.popen(gethelpi+gethelpd+" -?")
        for gethelpo in gethelpo.readlines():
            gethelpd=gethelpd+str(gethelpo)
        notepad.insert(0.0, str(gethelpd))    
    elif (gethelpi==""):
        messagebox.showinfo(title="Error", message="Error. Try again!")
#Date and time
def runtimedate():     #edit menu Time/Date option
    now = datetime.now()
    # dd/mm/YY H:M:S
    dtString = now.strftime("%d/%m/%Y %H:%M:%S")
    label = messagebox.showinfo("Time/Date", dtString)

#---Misc options---
#Command line to notepad input/output
def runcommand():
    runcommandd=""
    runcommandi=simpledialog.askstring(title="Run command",prompt="Enter command:")
    if runcommandi is not None and runcommandi != "":
        runcommando=os.popen(runcommandd+runcommandi)
        for runcommando in runcommando.readlines():
            runcommandd=runcommandd+str(runcommando)+"\n"
        notepad.insert(0.0, str(runcommandd))    
    elif (runcommandi==""):
        messagebox.showinfo(title="Error", message="Error. Try again!")
#-------------------------------------------------------------------------------------------------------------------------------------------

#Base window setup--------------------------------------------------------------------------------------------------------------------------
#---main program configurations---
app = Tk() #sets up the base window
app.geometry('800x600') # sets up the width and height of the base window
app.title("Network testing application") # sets up the title of the base window.
app.resizable()

#---appmenu---
appmenu = Menu(app) # sets up the menu on the base window.

#---Notepad menu---
#creating scrollable notepad window
notepad = ScrolledText(app)
notepad.pack(side = 'bottom', fill = 'x')
#-------------------------------------------------------------------------------------------------------------------------------------------

#User input functions-----------------------------------------------------------------------------------------------------------------------
#---appmenu options---
#File menu
filemenu = Menu(appmenu, tearoff=0) # Sets the menu with 0 means the menu is fixed in place. 1 means the menu can be torn off.
filesubmenu = Menu(filemenu, tearoff=0)
filemenu.add_command(label="Open", command=cmdOpen) # first option of the file menu
filemenu.add_cascade(label="Save options", menu=filesubmenu) # second option of the file menu 
filesubmenu.add_command(label="Save", command=cmdSave) # last option of the file menu
filesubmenu.add_command(label="Save as", command=cmdSaveAs)
#Notepad options menu
editmenu = Menu(appmenu, tearoff=0)
editsubmenu = Menu(editmenu, tearoff=0)
editmenu.add_separator()
editmenu.add_command(label="Copy", command=cmdCopy)
editmenu.add_command(label="Cut", command=cmdCut)
editmenu.add_command(label="Paste", command=cmdPaste)
editmenu.add_separator()
editmenu.add_cascade(label="Text tools", menu=editsubmenu)
editsubmenu.add_command(label="Find Text", command=cmdFind)
editsubmenu.add_command(label="Select All", command=cmdSelectAll)
editsubmenu.add_command(label="Clear All", command=cmdClear)
#Program window
programmenu = Menu(appmenu, tearoff=0)
programmenu.add_command(label="Notepad", command=runnotepad)
programmenu.add_command(label="System Info", command=runsysinf)
programmenu.add_command(label="Task List", command=runtasklist)
programmenu.add_command(label="Calculator", command=runcalc)
#commandmenu window
commandmenu = Menu(appmenu, tearoff=0)
commandmenu.add_command(label="IP Configuration", command=runipconf)
commandmenu.add_command(label="Address Resolution", command=runarp)
commandmenu.add_command(label="Ping", command=runping)
commandmenu.add_command(label="Nslookup", command=runnslookup)
commandmenu.add_command(label="Trace Route", command=runtraceroute)
commandmenu.add_command(label="Network statistics",command=runnetstat)
#Web menu
webmenu = Menu(appmenu,tearoff=0)
cyframemenu = Menu(webmenu,tearoff=0)
dorkmenu = Menu(webmenu, tearoff=0)
webtoolmenu = Menu(webmenu, tearoff=0)
webmenu.add_cascade(label="Website tools",menu=webtoolmenu)
webmenu.add_cascade(label= "Cyber security documents", menu=cyframemenu)
webmenu.add_cascade(label="Google dorks",menu=dorkmenu)
#Web tools menu
webtoolmenu.add_command(label="whatsmyname",command=namesearch)
webtoolmenu.add_command(label="urlScan.io",command=openrurlscan)
webtoolmenu.add_command(label="VirusTotal",command=openvirusscan)
webtoolmenu.add_command(label="CyberChef",command=opencyberchef)

#Cyber security framework sites
cyframemenu.add_command(label="OSINT Framework",command=openosint)
cyframemenu.add_command(label="Attack Mitre",command=openmitre)
#Dork menu
dorkmenu.add_command(label="INURL", command=runinurl)
dorkmenu.add_command(label="INTITLE",command=runintitle)
dorkmenu.add_command(label="INTEXT",command=runintext)
#Infomenu window
infomenu = Menu(appmenu, tearoff=0)
infomenu.add_command(label="Command-line help", command=gethelp)
infomenu.add_command(label="Time and date", command=runtimedate)
#Main menu option in appmenu
appmenu.add_cascade(label="File", menu=filemenu) # makes the options underneath File cascade or dropdown
appmenu.add_cascade(label="Edit", menu=editmenu)
appmenu.add_cascade(label="Utilities", menu=programmenu)
appmenu.add_cascade(label="Websites",menu=webmenu)
appmenu.add_cascade(label="Network testing", menu=commandmenu)
appmenu.add_cascade(label="Information", menu=infomenu)
#---Misc options---

#Focus option
appmenu.focus_set()
app.configure(menu=appmenu) # shows the appmenu on the base window 

app.mainloop() # makes the base window sit on top of the desktop forever
