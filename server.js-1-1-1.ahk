#Requires AutoHotkey v2.0
#SingleInstance Force

; =========================
; PASSWORD PROTECTION
; =========================
PASSWORD := "Ethiopia@2025"
ib := InputBox("Enter password to open Habesha Dash:", "Protected Tool", "Password")
if (ib.Result != "OK" || ib.Value != PASSWORD) {
  MsgBox("Access denied.")
  ExitApp
}

; =========================
; CONFIG
; =========================
base := "C:\Users\wedaj\OneDrive\Documents\Habesha"
clientsBase := base "\02 Clients"
taxYearsFile := base "\_settings_taxyears.txt"

; Signature formatting in Word
SIGN_NAME := "Liyou Wedaj Birhane"
SIGN_FONT := "Brush Script MT"
SIGN_SIZE := 26

taxYears := LoadTaxYears()

folders := Map(
  "01 Work",      base "\01 Work",
  "02 Clients",   clientsBase,
  "03 Finance",   base "\03 Finance",
  "04 Personal",  base "\04 Personal",
  "05 Downloads", base "\05 Downloads"
)

; =========================
; GUI (Main)
; =========================
gui1 := Gui("+AlwaysOnTop -MaximizeBox -MinimizeBox", "Habesha Folders")
gui1.SetFont("s10", "Segoe UI")
gui1.MarginX := 12
gui1.MarginY := 12

; =========================
; HELPERS
; =========================
EnsureDir(p) {
  if !DirExist(p)
    DirCreate(p)
}

AskYesNo(msg, title := "Confirm") {
  return MsgBox(msg, title, "YesNo Icon?") = "Yes"
}

InputBoxVal(prompt, title := "Input", default := "") {
  ib := InputBox(prompt, title, , default)
  if (ib.Result != "OK")
    return ""
  return Trim(ib.Value)
}

SafeName(input) {
  s := Trim(input)
  invalid := '<>:"/\|?*'
  Loop Parse, invalid
    s := StrReplace(s, A_LoopField, "_")
  s := RegExReplace(s, "\s+", " ")
  return SubStr(s, 1, 120)
}

WriteTextFile(p, c) {
  try FileDelete(p)
  FileAppend(c, p, "UTF-8")
}

ReadTextFile(p) {
  if !FileExist(p)
    return ""
  return FileRead(p, "UTF-8")
}

TodayISO() {
  return FormatTime(A_Now, "yyyy-MM-dd")
}

JoinArray(arr, delim := "`n") {
  out := ""
  for i, v in arr
    out .= (i = 1 ? "" : delim) v
  return out
}

SortArray(arr) {
  if !IsObject(arr) || arr.Length = 0
    return arr
  s := JoinArray(arr, "`n")
  s := Sort(s, "D`n")
  parts := StrSplit(s, "`n", "`r")
  sorted := []
  for , v in parts {
    v := Trim(v)
    if (v != "")
      sorted.Push(v)
  }
  return sorted
}

; =========================
; TAX YEARS
; =========================
LoadTaxYears() {
  global taxYearsFile
  arr := []
  if FileExist(taxYearsFile) {
    for line in StrSplit(FileRead(taxYearsFile, "UTF-8"), "`n", "`r") {
      v := Trim(line)
      if (v != "")
        arr.Push(v)
    }
  }
  if (arr.Length = 0) {
    arr.Push("2024-25")
    arr.Push("2025-26")
    SaveTaxYears(arr)
  }
  return arr
}

SaveTaxYears(optionalArr := "") {
  global taxYearsFile, taxYears
  if IsObject(optionalArr)
    taxYears := optionalArr

  EnsureDir(RegExReplace(taxYearsFile, "\\[^\\]+$", ""))
  content := ""
  for , y in taxYears
    content .= y "`r`n"
  WriteTextFile(taxYearsFile, content)
}

; =========================
; BASE STRUCTURE
; =========================
EnsureBaseStructure(showMsg := false) {
  global base, folders
  EnsureDir(base)
  for , p in folders
    EnsureDir(p)

  EnsureDir(base "\02 Clients")
  EnsureDir(base "\04 Personal\Church Related")

  if showMsg
    MsgBox("Checked/created base folders under:`n" base)
}

OpenFolderBtn(btn, *) {
  try {
    EnsureDir(btn.Path)
    Run(btn.Path)
  } catch as e {
    MsgBox("Could not open folder:`n" btn.Path "`n`n" e.Message)
  }
}

; =========================
; CLIENT INFO
; =========================
ClientInfoFile(clientFolder) {
  return clientFolder "\_client_info.txt"
}

DetectClientType(clientFolder) {
  name := RegExReplace(clientFolder, "^.*\\", "")
  if InStr(name, "Ltd") || InStr(name, "LTD") || InStr(name, "Limited")
    return "Limited Company"
  return "Self-Employed"
}

EnsureClientInfo(clientFolder, clientType) {
  p := ClientInfoFile(clientFolder)
  if FileExist(p)
    return

  content :=
(
"Client Name: " RegExReplace(clientFolder, "^.*\\", "") "`r`n"
"Client Type: " clientType "`r`n"
"Created: " TodayISO() "`r`n"
"Bookkeeping Required: No" "`r`n"
"VAT Registered: No" "`r`n"
"PAYE/Payroll: No" "`r`n"
"MTD ITSA: No" "`r`n"
"Self Assessment: No" "`r`n"
"Home Office Applications: No" "`r`n"
"Other Extra Service: No" "`r`n"
"Directors Count: 1" "`r`n"
)
  WriteTextFile(p, content)
}

GetRegistrationDate(clientFolder) {
  EnsureClientInfo(clientFolder, DetectClientType(clientFolder))
  info := ReadTextFile(ClientInfoFile(clientFolder))
  if RegExMatch(info, "m)^\s*Created:\s*(\d{4}-\d{2}-\d{2})\s*$", &m)
    return Trim(m[1])
  return TodayISO()
}

ReadClientFlags(clientFolder) {
  EnsureClientInfo(clientFolder, DetectClientType(clientFolder))
  info := ReadTextFile(ClientInfoFile(clientFolder))

  f := Map()
  f["type"] := RegExMatch(info, "Client Type:\s*(.*)", &m) ? Trim(m[1]) : DetectClientType(clientFolder)
  f["bk"] := InStr(info, "Bookkeeping Required: Yes")
  f["vat"] := InStr(info, "VAT Registered: Yes")
  f["paye"] := InStr(info, "PAYE/Payroll: Yes")
  f["mtd"] := InStr(info, "MTD ITSA: Yes")
  f["sa"] := InStr(info, "Self Assessment: Yes")
  f["ho"] := InStr(info, "Home Office Applications: Yes")
  f["extra"] := InStr(info, "Other Extra Service: Yes")
  f["directors"] := RegExMatch(info, "Directors Count:\s*(\d+)", &d) ? (d[1] + 0) : 1
  return f
}

SetClientInfo(clientFolder, clientType, bk, vat, paye, mtd, sa, ho, directors, extra) {
  p := ClientInfoFile(clientFolder)
  name := RegExReplace(clientFolder, "^.*\\", "")
  created := GetRegistrationDate(clientFolder) ; keep original

  content :=
(
"Client Name: " name "`r`n"
"Client Type: " clientType "`r`n"
"Created: " created "`r`n"
"Updated: " TodayISO() "`r`n"
"Bookkeeping Required: " (bk ? "Yes" : "No") "`r`n"
"VAT Registered: " (vat ? "Yes" : "No") "`r`n"
"PAYE/Payroll: " (paye ? "Yes" : "No") "`r`n"
"MTD ITSA: " (mtd ? "Yes" : "No") "`r`n"
"Self Assessment: " (sa ? "Yes" : "No") "`r`n"
"Home Office Applications: " (ho ? "Yes" : "No") "`r`n"
"Other Extra Service: " (extra ? "Yes" : "No") "`r`n"
"Directors Count: " directors "`r`n"
)
  WriteTextFile(p, content)
}

; =========================
; FOLDER STRUCTURE
; =========================
CreateCoreClientFolders(clientPath) {
  EnsureDir(clientPath "\00 Engagement Letter")

  idBase := clientPath "\01 Proof of ID"
  EnsureDir(idBase)
  EnsureDir(idBase "\01 Passport - BRP - eVisa")
  EnsureDir(idBase "\02 Proof of Address")
  EnsureDir(idBase "\03 Signed Engagement Letter")

  EnsureDir(clientPath "\02 Compliance")
}

CreateSelfAssessmentStructure(clientPath, taxYearsArr) {
  saBase := clientPath "\02 Compliance\01 Self Assessment"
  EnsureDir(saBase)

  for , y in taxYearsArr {
    yearBase := saBase "\" y
    EnsureDir(yearBase)
    EnsureDir(yearBase "\01 Income documents")
    EnsureDir(yearBase "\02 Expense records")
    EnsureDir(yearBase "\03 Bank statements")
    EnsureDir(yearBase "\04 Other SA-related compliance files")
    EnsureDir(yearBase "\05 CIS statements")
    EnsureDir(yearBase "\06 Pensions & Benefits")
    EnsureDir(yearBase "\07 Final & Submitted")
  }
}

CreateHomeOfficeStructure(clientPath) {
  hoBase := clientPath "\02 Compliance\05 Home Office Applications"
  EnsureDir(hoBase)
  EnsureDir(hoBase "\01 Forms")
  EnsureDir(hoBase "\02 Supporting Documents")
  EnsureDir(hoBase "\03 ID & Immigration")
  EnsureDir(hoBase "\04 Payments & Appointments")
  EnsureDir(hoBase "\05 Submitted & Decisions")
}

CreateLimitedCompanyStructure(clientPath, taxYearsArr, hasVat, hasPaye) {
  ctBase := clientPath "\02 Compliance\01 Corporation Tax"
  EnsureDir(ctBase)

  for , y in taxYearsArr {
    yearBase := ctBase "\" y
    EnsureDir(yearBase)
    EnsureDir(yearBase "\01 Income (Sales)")
    EnsureDir(yearBase "\02 Expenses (Purchase invoices & receipts)")
    EnsureDir(yearBase "\03 Bank statements")
    EnsureDir(yearBase "\04 Credit cards statements")
    EnsureDir(yearBase "\05 Cash summary")
    EnsureDir(yearBase "\06 Directors Loan Account")
    EnsureDir(yearBase "\07 Loan agreements")
    EnsureDir(yearBase "\08 HP & Lease agreements")
    EnsureDir(yearBase "\09 Interest statements")
    EnsureDir(yearBase "\10 Grants & other income")
    EnsureDir(yearBase "\11 Previous year documents")
    EnsureDir(yearBase "\12 Other workpapers")
    EnsureDir(yearBase "\13 Final & Submitted")
  }

  if (hasVat) {
    vatBase := clientPath "\02 Compliance\02 VAT"
    EnsureDir(vatBase)
    for , y in taxYearsArr {
      yb := vatBase "\" y
      EnsureDir(yb)
      EnsureDir(yb "\01 VAT Returns")
      EnsureDir(yb "\02 Sales (VAT)")
      EnsureDir(yb "\03 Purchases (VAT)")
      EnsureDir(yb "\04 VAT workings")
      EnsureDir(yb "\05 Final & Submitted")
    }
  }

  if (hasPaye) {
    payeBase := clientPath "\02 Compliance\03 Payroll (PAYE)"
    EnsureDir(payeBase)
    for , y in taxYearsArr {
      yb := payeBase "\" y
      EnsureDir(yb)
      EnsureDir(yb "\01 Employee details")
      EnsureDir(yb "\02 Timesheets")
      EnsureDir(yb "\03 Payslips")
      EnsureDir(yb "\04 RTI submissions")
      EnsureDir(yb "\05 Pension (Auto-enrolment)")
      EnsureDir(yb "\06 P60 P45")
      EnsureDir(yb "\07 Final & Submitted")
    }
  }
}

ApplyNewStructureToAllClients(*) {
  global clientsBase, taxYears
  if !DirExist(clientsBase) {
    MsgBox("Clients folder not found:`n" clientsBase)
    return
  }
  if !AskYesNo("This will create missing folders for ALL clients under:`n" clientsBase "`n`nContinue?", "Apply Structure")
    return

  count := 0
  processed := 0

  loop files clientsBase "\*", "D" {
    count++
    clientPath := clientsBase "\" A_LoopFileName
    CreateCoreClientFolders(clientPath)

    f := ReadClientFlags(clientPath)
    if (f["sa"])
      CreateSelfAssessmentStructure(clientPath, taxYears)
    if (f["type"] = "Limited Company")
      CreateLimitedCompanyStructure(clientPath, taxYears, f["vat"], f["paye"])
    if (f["ho"])
      CreateHomeOfficeStructure(clientPath)

    processed++
  }

  MsgBox("Done ✅`nClients found: " count "`nClients processed: " processed)
}

; =========================
; CLIENT LIST
; =========================
GetClientList() {
  global clientsBase
  arr := []
  if !DirExist(clientsBase)
    return arr
  loop files clientsBase "\*", "D"
    arr.Push(A_LoopFileName)
  return SortArray(arr)
}

; =========================
; CREATE CLIENT
; =========================
CreateClient(clientType) {
  global clientsBase
  EnsureDir(clientsBase)

  name := InputBoxVal("Enter client name:", "New " clientType)
  if (name = "")
    return ""

  safe := SafeName(name)
  p := clientsBase "\" safe
  EnsureDir(p)

  CreateCoreClientFolders(p)
  EnsureClientInfo(p, clientType)
  return p
}

; =========================
; NEW CLIENT FLOWS
; =========================
NewSelfEmployed(*) {
  global taxYears
  p := CreateClient("Self-Employed")
  if (p = "")
    return

  bk := AskYesNo("Bookkeeping required for this client?")
  vat := AskYesNo("VAT registered?")
  paye := AskYesNo("Payroll (PAYE) required?")
  mtd := AskYesNo("MTD ITSA required?")
  sa := AskYesNo("Self Assessment required?")
  ho := AskYesNo("Home Office applications support required?")
  ex := AskYesNo("Any other extra services?")

  SetClientInfo(p, "Self-Employed", bk, vat, paye, mtd, sa, ho, 1, ex)
  if (sa) CreateSelfAssessmentStructure(p, taxYears)
  if (ho) CreateHomeOfficeStructure(p)

  if AskYesNo("Generate engagement letter (Word + PDF) now?")
    GenerateEngagementLetterForClientPrompt(p)

  Run(p)
}

NewLandlord(*) {
  global taxYears
  p := CreateClient("Landlord")
  if (p = "")
    return

  sa := AskYesNo("Self Assessment required for landlord?")
  bk := AskYesNo("Bookkeeping required?")
  vat := AskYesNo("VAT registered? (rare for landlords)")
  paye := false
  mtd := AskYesNo("MTD ITSA required?")
  ho := AskYesNo("Home Office applications support required?")
  ex := AskYesNo("Any other extra services?")

  SetClientInfo(p, "Landlord", bk, vat, paye, mtd, sa, ho, 1, ex)
  if (sa) CreateSelfAssessmentStructure(p, taxYears)
  if (ho) CreateHomeOfficeStructure(p)

  if AskYesNo("Generate engagement letter (Word + PDF) now?")
    GenerateEngagementLetterForClientPrompt(p)

  Run(p)
}

NewLimitedCompany(*) {
  global taxYears
  p := CreateClient("Limited Company")
  if (p = "")
    return

  bk := AskYesNo("Bookkeeping required?")
  vat := AskYesNo("VAT registered?")
  paye := AskYesNo("Payroll (PAYE) required?")
  mtd := false
  sa := false
  ho := AskYesNo("Home Office applications support required?")
  ex := AskYesNo("Any other extra services?")

  d := InputBoxVal("How many directors?", "Directors", "1")
  directors := (d = "" ? 1 : (d + 0))
  if (directors < 1)
    directors := 1

  SetClientInfo(p, "Limited Company", bk, vat, paye, mtd, sa, ho, directors, ex)
  CreateLimitedCompanyStructure(p, taxYears, vat, paye)
  if (ho) CreateHomeOfficeStructure(p)

  if AskYesNo("Generate engagement letter (Word + PDF) now?")
    GenerateEngagementLetterForClientPrompt(p)

  Run(p)
}

NewOtherClient(*) {
  p := CreateClient("Other Client")
  if (p = "")
    return

  ho := AskYesNo("Home Office applications support required?")
  ex := AskYesNo("Any other extra services?")

  SetClientInfo(p, "Other Client", false, false, false, false, false, ho, 1, ex)
  if (ho) CreateHomeOfficeStructure(p)

  if AskYesNo("Generate engagement letter (Word + PDF) now?")
    GenerateEngagementLetterForClientPrompt(p)

  Run(p)
}

; =========================
; UPDATE REGISTRATION GUI
; =========================
UpdateClientRegistration(*) {
  global clientsBase, taxYears

  list := GetClientList()
  if (list.Length = 0) {
    MsgBox("No clients found in:`n" clientsBase)
    return
  }

  g := Gui("+AlwaysOnTop", "Edit Client Registration (Services)")
  g.SetFont("s10", "Segoe UI")
  g.MarginX := 12, g.MarginY := 12

  g.Add("Text",, "Select client:")
  ddlClient := g.Add("DropDownList", "w520 Choose1", list)

  g.Add("Text", "y+10", "Client Type:")
  ddlType := g.Add("DropDownList", "w260", ["Self-Employed","Landlord","Limited Company","Other Client"])

  g.Add("Text", "x+20 yp", "Directors (Ltd only):")
  edDirectors := g.Add("Edit", "w80", "1")

  g.Add("GroupBox", "xm y+16 w560 h190", "Services")
  cbBK   := g.Add("CheckBox", "xm+20 yp+30", "Bookkeeping Required")
  cbVAT  := g.Add("CheckBox", "xm+20 y+10", "VAT Registered")
  cbPAYE := g.Add("CheckBox", "xm+20 y+10", "PAYE / Payroll")
  cbMTD  := g.Add("CheckBox", "xm+20 y+10", "MTD ITSA")
  cbSA   := g.Add("CheckBox", "xm+20 y+10", "Self Assessment")
  cbHO   := g.Add("CheckBox", "xm+280 yp-80", "Home Office Applications")
  cbEX   := g.Add("CheckBox", "xm+280 y+10", "Other Extra Service")

  g.Add("Text", "xm y+10 w560", "Unticking a service will NOT delete folders. It only updates registration.")

  btnSave := g.Add("Button", "xm y+14 w180 h34 Default", "Save Changes")
  btnOpen := g.Add("Button", "x+10 w180 h34", "Open Client Folder")
  btnCancel := g.Add("Button", "x+10 w180 h34", "Cancel")

  LoadUIFromClient(*) {
    clientName := ddlClient.Text
    clientPath := clientsBase "\" clientName
    f := ReadClientFlags(clientPath)

    ddlType.Text := f["type"]
    edDirectors.Text := f["directors"]

    cbBK.Value   := f["bk"]    ? 1 : 0
    cbVAT.Value  := f["vat"]   ? 1 : 0
    cbPAYE.Value := f["paye"]  ? 1 : 0
    cbMTD.Value  := f["mtd"]   ? 1 : 0
    cbSA.Value   := f["sa"]    ? 1 : 0
    cbHO.Value   := f["ho"]    ? 1 : 0
    cbEX.Value   := f["extra"] ? 1 : 0

    edDirectors.Enabled := (ddlType.Text = "Limited Company")
  }

  SaveChanges(*) {
    clientName := ddlClient.Text
    clientPath := clientsBase "\" clientName

    ct := ddlType.Text
    bk := (cbBK.Value = 1)
    vat := (cbVAT.Value = 1)
    paye := (cbPAYE.Value = 1)
    mtd := (cbMTD.Value = 1)
    sa := (cbSA.Value = 1)
    ho := (cbHO.Value = 1)
    ex := (cbEX.Value = 1)

    d := RegExReplace(Trim(edDirectors.Text), "[^0-9]", "")
    directors := (d = "" ? 1 : (d + 0))
    if (directors < 1)
      directors := 1

    CreateCoreClientFolders(clientPath)
    SetClientInfo(clientPath, ct, bk, vat, paye, mtd, sa, ho, directors, ex)

    if (sa)
      CreateSelfAssessmentStructure(clientPath, taxYears)
    if (ct = "Limited Company")
      CreateLimitedCompanyStructure(clientPath, taxYears, vat, paye)
    if (ho)
      CreateHomeOfficeStructure(clientPath)

    MsgBox("Saved ✅`n`nRegistration updated for: " clientName)
  }

  ddlClient.OnEvent("Change", LoadUIFromClient)
  ddlType.OnEvent("Change", (*) => (edDirectors.Enabled := (ddlType.Text = "Limited Company")))
  btnOpen.OnEvent("Click", (*) => Run(clientsBase "\" ddlClient.Text))
  btnCancel.OnEvent("Click", (*) => g.Destroy())
  btnSave.OnEvent("Click", SaveChanges)

  LoadUIFromClient()
  g.Show("AutoSize")
}

; =========================
; ENGAGEMENT LETTER (FULL + service wording matches client type)
; Generates DOCX + PDF via Word
; =========================
ServiceWording(clientType, bk, vat, paye, mtd, sa, ho, extra, directors := 1) {
  s := ""

  if (clientType = "Limited Company") {
    s .= "• Corporation Tax return and statutory accounts: As agreed`r`n"
    s .= "• Companies House support (confirmation statement / filing support): As agreed`r`n"
    s .= "• Directors (" directors "): Included for year-end/ payroll coordination`r`n"
  } else if (clientType = "Landlord") {
    s .= "• Self Assessment (property income): " (sa ? "As agreed" : "No") "`r`n"
    s .= "• Rental income & expense schedule support: " (sa ? "As agreed" : "No") "`r`n"
  } else if (clientType = "Self-Employed") {
    s .= "• Self Assessment (sole trader): " (sa ? "As agreed" : "No") "`r`n"
  } else {
    s .= "• General advisory / support services: As agreed`r`n"
  }

  ; Common add-ons
  s .= "• Bookkeeping & bank reconciliation: " (bk ? "As agreed" : "No") "`r`n"
  s .= "• VAT / MTD VAT returns: " (vat ? "As agreed" : "No") "`r`n"
  s .= "• Payroll (PAYE/RTI), payslips, P60/P45: " (paye ? "As agreed" : "No") "`r`n"
  s .= "• MTD for Income Tax (ITSA): " (mtd ? "As agreed" : "No") "`r`n"
  s .= "• Home Office applications (forms + supporting documents): " (ho ? "As agreed" : "No") "`r`n"
  s .= "• Other extra service: " (extra ? "As agreed" : "No") "`r`n"

  return s
}

EngagementLetterText(clientName, clientType, bk, vat, paye, mtd, sa, ho, feeText, paymentTerms, regDateISO, directors := 1, extra := false) {
  global SIGN_NAME
  services := ServiceWording(clientType, bk, vat, paye, mtd, sa, ho, extra, directors)

  return
(
"HABESHA TAX & SUPPORT LTD`r`n"
"ENGAGEMENT LETTER`r`n"
"=====================================`r`n"
"`r`n"
"Client Name: " clientName "`r`n"
"Client Type: " clientType "`r`n"
"Date of registration: " regDateISO "`r`n"
"`r`n"
"1) Purpose`r`n"
"This letter confirms the scope of services agreed between the Client and Habesha Tax & Support Ltd (the Advisor).`r`n"
"`r`n"
"2) Scope of services (as agreed)`r`n"
services
"`r`n"
"3) Client responsibilities`r`n"
"• Provide complete and accurate information on time`r`n"
"• Keep and provide records and supporting documents`r`n"
"• Review drafts and confirm approval before submission/filing`r`n"
"`r`n"
"4) Advisor responsibilities`r`n"
"• Prepare agreed work using the information supplied`r`n"
"• Keep your information confidential and secure`r`n"
"• Contact you if clarification or additional information is required`r`n"
"`r`n"
"5) Fees and payment`r`n"
"Fee agreed: " feeText "`r`n"
"Payment terms: " paymentTerms "`r`n"
"`r`n"
"6) Important notes`r`n"
"• We are not responsible for penalties/interest caused by late or missing information from the Client`r`n"
"• If your circumstances change (e.g. VAT registration, payroll start), you must inform us immediately`r`n"
"`r`n"
"7) Signatures`r`n"
"Client signature: ______________________    Date: __________`r`n"
"Habesha Tax & Support Ltd: " SIGN_NAME "    Date: " regDateISO "`r`n"
)
}

PromptFeeInfo(clientName := "") {
  g := Gui("+AlwaysOnTop", "Agreed Fee")
  g.SetFont("s10", "Segoe UI")
  g.MarginX := 12, g.MarginY := 12

  g.Add("Text",, "Client: " (clientName != "" ? clientName : ""))
  g.Add("Text", "w520", "Enter agreed fee, then choose payment type.")

  g.Add("Text", "y+10", "Fee amount (e.g. 200 or 200.00):")
  edFee := g.Add("Edit", "w200", "")

  g.Add("Text", "y+10", "Payment type:")
  ddl := g.Add("DropDownList", "w260 Choose1", ["One-off", "Monthly Direct Debit"])

  g.Add("Text", "y+10", "DD collection day (optional, 1-28):")
  edDay := g.Add("Edit", "w80", "")

  result := false

  btnOk := g.Add("Button", "y+16 w240 Default", "OK")
  btnCancel := g.Add("Button", "x+40 w240", "Cancel")

  btnCancel.OnEvent("Click", (*) => g.Destroy())

  btnOk.OnEvent("Click", (*) => (
    feeRaw := Trim(edFee.Text),
    feeRaw = ""
      ? MsgBox("Please enter a fee amount.")
      : (
          feeNum := RegExReplace(feeRaw, "[^0-9\\.]", ""),
          feeNum := (feeNum = "" ? feeRaw : feeNum),
          payType := ddl.Text,
          day := RegExReplace(Trim(edDay.Text), "[^0-9]", ""),
          feeText := (InStr(feeRaw, "£") ? feeRaw : "£" feeNum),
          paymentTerms := (payType = "One-off")
            ? "One-off payment (due on engagement / as agreed)."
            : ((day != "" && (day+0) >= 1 && (day+0) <= 28)
                ? "Monthly Direct Debit, collected on day " day " of each month."
                : "Monthly Direct Debit."),
          result := { feeText: feeText, paymentTerms: paymentTerms },
          g.Destroy()
        )
  ))

  g.Show("AutoSize")
  WinWaitClose("Agreed Fee")
  return result
}

; Create DOCX + PDF from plain text using Word
SaveWordAndPdfFromText(text, docxPath, pdfPath) {
  global SIGN_NAME, SIGN_FONT, SIGN_SIZE
  word := ""
  doc := ""
  try {
    word := ComObject("Word.Application")
    word.Visible := false
    doc := word.Documents.Add()
    doc.Content.Text := text

    ; Basic formatting (optional)
    doc.Content.Font.Name := "Calibri"
    doc.Content.Font.Size := 11

    ; Make title bold (first lines)
    rng := doc.Range(0, 0)
    rng.SetRange(0, 0) ; no-op safety

    ; Style signature name
    r := doc.Content
    r.Find.ClearFormatting()
    r.Find.Text := SIGN_NAME
    if (r.Find.Execute()) {
      r.Font.Name := SIGN_FONT
      r.Font.Size := SIGN_SIZE
    }

    ; Save
    doc.SaveAs2(docxPath, 16) ; wdFormatXMLDocument
    doc.ExportAsFixedFormat(pdfPath, 17) ; wdExportFormatPDF

    doc.Close(false)
    word.Quit()
    return true
  } catch as e {
    try doc.Close(false)
    try word.Quit()
    MsgBox("Word/PDF generation failed.`n`nMake sure Microsoft Word is installed.`n`n" e.Message)
    return false
  }
}

GenerateEngagementLetterForClientPrompt(clientFolder, clientName := "") {
  info := PromptFeeInfo(clientName)
  if !info
    return
  GenerateEngagementLetterForClient(clientFolder, info.feeText, info.paymentTerms)
}

GenerateEngagementLetterForClient(clientFolder, feeText, paymentTerms) {
  global clientsBase

  clientName := RegExReplace(clientFolder, "^.*\\", "")
  f := ReadClientFlags(clientFolder)

  target := clientFolder "\00 Engagement Letter"
  EnsureDir(target)

  regDate := GetRegistrationDate(clientFolder)

  content := EngagementLetterText(
    clientName,
    f["type"],
    f["bk"], f["vat"], f["paye"], f["mtd"],
    f["sa"], f["ho"],
    feeText, paymentTerms, regDate,
    f["directors"], f["extra"]
  )

  docx := target "\Engagement Letter - " clientName " - " regDate ".docx"
  pdf  := target "\Engagement Letter - " clientName " - " regDate ".pdf"

  ok := SaveWordAndPdfFromText(content, docx, pdf)
  if (ok) {
    MsgBox("Engagement letter saved:`n`n" docx "`n" pdf)
  } else {
    ; fallback: save txt if Word fails
    txt := target "\Engagement Letter - " clientName " - " regDate ".txt"
    WriteTextFile(txt, content)
    MsgBox("Saved as TXT only (Word failed):`n" txt)
  }

  Run(target)
}

GenerateEngagementLetterUI(*) {
  global clientsBase
  list := GetClientList()
  if (list.Length = 0) {
    MsgBox("No clients found.")
    return
  }

  g := Gui("+AlwaysOnTop", "Generate Engagement Letter")
  g.SetFont("s10", "Segoe UI")
  g.MarginX := 12, g.MarginY := 12

  g.Add("Text",, "Select client:")
  ddl := g.Add("DropDownList", "w520 Choose1", list)

  btnGo := g.Add("Button", "xm y+14 w240 h34 Default", "Generate Letter")
  btnCancel := g.Add("Button", "x+10 w240 h34", "Cancel")

  btnCancel.OnEvent("Click", (*) => g.Destroy())
  btnGo.OnEvent("Click", (*) => (
    clientName := ddl.Text,
    clientPath := clientsBase "\" clientName,
    GenerateEngagementLetterForClientPrompt(clientPath, clientName),
    g.Destroy()
  ))

  g.Show("AutoSize")
}

; =========================
; MAIN UI BUTTONS
; =========================
EnsureBaseStructure(false)

for name, path in folders {
  b := gui1.Add("Button", "w240 h34", name)
  b.Path := path
  b.OnEvent("Click", OpenFolderBtn)
}

gui1.Add("Text", "w240 h10")
gui1.Add("Button", "w240 h34", "➕ New Self-Employed").OnEvent("Click", NewSelfEmployed)
gui1.Add("Button", "w240 h34", "➕ New Landlord").OnEvent("Click", NewLandlord)
gui1.Add("Button", "w240 h34", "➕ New Limited Company").OnEvent("Click", NewLimitedCompany)
gui1.Add("Button", "w240 h34", "➕ New Other Client").OnEvent("Click", NewOtherClient)

gui1.Add("Text", "w240 h10")
gui1.Add("Button", "w240 h34", "🧱 Apply New Structure to ALL Clients").OnEvent("Click", ApplyNewStructureToAllClients)
gui1.Add("Button", "w240 h34", "✏️ Update Client Registration").OnEvent("Click", UpdateClientRegistration)
gui1.Add("Button", "w240 h34", "📝 Generate Engagement Letter").OnEvent("Click", GenerateEngagementLetterUI)
gui1.Add("Button", "w240 h34", "⚙️ Create Missing Base Folders").OnEvent("Click", (*) => EnsureBaseStructure(true))

gui1.Show("x20 y90 AutoSize")

A_TrayMenu.Delete()
A_TrayMenu.Add("Show / Hide", (*) => gui1.Visible ? gui1.Hide() : gui1.Show())
A_TrayMenu.Add("Exit", (*) => ExitApp())
