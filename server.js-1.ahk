#Requires AutoHotkey v2.0

#Requires AutoHotkey v2.0
#SingleInstance Force

; =========================
; CONFIG (edit if needed)
; =========================
BASE := "C:\Users\wedaj\OneDrive\Documents\Habesha"
TEMPLATES_DIR := BASE "\Templates"
OUT_DIR := BASE "\Engagement Letters"
DB_INI := BASE "\_fee_agreements.ini"   ; saves per-client fee choice so you don't retype

TEMPLATE_INDIV := TEMPLATES_DIR "\Engagement_Template_Individual.docx"
TEMPLATE_LTD   := TEMPLATES_DIR "\Engagement_Template_Limited.docx"

DirCreate(OUT_DIR)

; =========================
; DASHBOARD UI
; =========================
main := Gui("+AlwaysOnTop", "Habesha Dashboard")
main.SetFont("s11")

main.AddText("w380", "Engagement Letter Generator (fills agreed fee into Word + PDF)")
main.AddText("y+12", "Client name:")
edClient := main.AddEdit("w380 vClientName")

main.AddText("y+10", "Client type:")
ddType := main.AddDropDownList("w380 Choose1 vClientType", ["Individual / Sole Trader", "Limited Company"])

btn := main.AddButton("y+16 w380 Default", "Generate Engagement Letter (Word + PDF)")
btn.OnEvent("Click", (*) => OnGenerate(edClient.Text, ddType.Text))

main.Show()

; =========================
; MAIN ACTION
; =========================
OnGenerate(clientName, clientTypeText) {
  global TEMPLATE_INDIV, TEMPLATE_LTD, OUT_DIR, DB_INI

  clientName := Trim(clientName)
  if (clientName = "") {
    MsgBox("Please enter the client name.")
    return
  }

  ; load last saved fee options for this client (handy)
  savedFeeType := IniRead(DB_INI, clientName, "fee_type", "One-off")
  savedAmount  := IniRead(DB_INI, clientName, "amount", "")
  savedDDDay   := IniRead(DB_INI, clientName, "dd_day", "")

  fee := FeeDialog(clientName, savedAmount, savedFeeType, savedDDDay)
  if (!fee)
    return

  ; store for next time
  IniWrite(fee.amount,  DB_INI, clientName, "amount")
  IniWrite(fee.feeType, DB_INI, clientName, "fee_type")
  IniWrite(fee.ddDay,   DB_INI, clientName, "dd_day")

  feeLine := BuildFeeLine(fee.amount, fee.feeType, fee.ddDay)

  tpl := (clientTypeText = "Limited Company") ? TEMPLATE_LTD : TEMPLATE_INDIV

  if !FileExist(tpl) {
    MsgBox("Template not found:`n" tpl "`n`nCreate the template file and try again.")
    return
  }

  safeClient := SafeFileName(clientName)
  dateStr := FormatTime(A_Now, "dd MMMM yyyy")

  outDocx := OUT_DIR "\Engagement Letter - " safeClient ".docx"
  outPdf  := OUT_DIR "\Engagement Letter - " safeClient ".pdf"

  ok := CreateLetterFromTemplate(tpl, outDocx, outPdf, Map(
    "{{CLIENT_NAME}}", clientName,
    "{{DATE}}", dateStr,
    "{{FEE_LINE}}", feeLine
  ))

  if (ok) {
    MsgBox("Created successfully:`n`n" outDocx "`n" outPdf)
    Run('explor
