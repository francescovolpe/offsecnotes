## Email header structure

| Field  | Details |
| ------------- | ------------- |
| From  | The sender's address.  |
| To  | The receiver's address, including CC and BCC.  |
| Date  |  Timestamp, when the email was sent.  |
| Subject  | The subject of the email.  |
| Return Path  | The return address of the reply, a.k.a. "Reply-To". If you reply to an email, the reply will go to the address mentioned in this field. |
| Domain Key and DKIM Signatures | Email signatures are provided by email services to identify and authenticate emails. |
| SPF  | Shows the server that was used to send the email. It will help to understand if the actual server is used to send the email from a specific domain.  |
| Message-ID  | Unique ID of the email.  |
| MIME-Version | Used MIME version. It will help to understand the delivered "non-text" contents and attachments.  |
| X-Headers  | The receiver mail providers usually add these fields. Provided info is usually experimental and can be different according to the mail provider. |
| X-Received  | Mail servers that the email went through. |
| X-Spam Status  | Spam score of the email. |
| X-Mailer  | Email client name. |

## Quick analysis

- Do the "From", "To", and "CC" fields contain valid addresses?
- Are the "From" and "To" fields the same?
- Are the "From" and "Return-Path" fields the same?
- Was the email sent from the correct server? (Email should have come from the official mail servers of the sender.)
- Does the "Message-ID" field exist, and is it valid?
- Do the hyperlinks redirect to suspicious/abnormal sites?
- Do the attachments consist of or contain malware?

## Tools
- Automated phishing analysis
  - [PhishTool](https://www.phishtool.com/) 
- Headers analysis, extracting attachments
  - [eml_analyzer](https://github.com/wahlflo/eml_analyzer) 
    - ``` emlAnalyzer -i file.eml --header --html -u --text --extract-all  ```
  - [Messageheader](https://toolbox.googleapps.com/apps/messageheader/analyzeheader)
  - [Message Header Analyzer](https://mha.azurewebsites.net/)
  - [Mail Header](https://mailheader.org/)
- Email reputation
  - [emailrep.io](https://emailrep.io/)
    - check sender and return path
- File / domain analyis
  - [VirusTotal](https://www.virustotal.com/)
  - [InQuest](https://labs.inquest.net/)
  - [IPinfo.io](https://ipinfo.io/)
  - [Urlscan.io](https://urlscan.io/)
  - [Talos Reputation](https://www.talosintelligence.com/reputation)
- Browser sandbox
  - Browserling
  - Wannabrowser
- URL Extractor
  - [URL Extractor](https://www.convertcsv.com/url-extractor.htm)
  - [Cyberchef extract URL](https://gchq.github.io/CyberChef/#recipe=Extract_URLs(false,false,false))
- Malware sandbox
  - [Any.Run](https://app.any.run/)
  - [Hybrid Analysis](https://www.hybrid-analysis.com/)
  - [Joesecurity](https://www.joesecurity.org/)
 
### Credits
TryHackMe: https://tryhackme.com/room/adventofcyber4
