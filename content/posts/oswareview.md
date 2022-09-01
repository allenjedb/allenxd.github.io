---
title: OSWA Review - Offensive Security
date: 2022-09-01
excerpt: "Offensive Security Web Assessor (OSWA) certification is a newly released course from Offensive Security, this course focusses on how to exploit common web vulnerabilities and exfiltrate data or gain code execution on the target web server"
categories:
  - Review
  - Certification
tags:
  - Offensive Security
ShowToc: true

---

Offensive Security Web Assessor (OSWA) certification is a newly released course from Offensive Security, this course focusses on how to exploit common web vulnerabilities and exfiltrate data or gain code execution on the target web server. 
<!--more-->

- CORS Misconfigurations
- Cross-Site Scripting
- SQL Injection
- Directory Traversal
- XML Enternal Entities
- Server-side Template Injection
- Command Execution
- IDOR
- Server-side Request Forgery

## Course Experience

Each topics in the course includes exercises that gives the practical experience feel to the students which I think is really good instead of just reading and watching the videos included in the course. Although, the exercise instructions can be improved as a couple of times from my experience where I got stuck as the instructions/questions are not clear enough. This is where the Discord community became really helpful though as there are community moderators that are ready help with every questions that we have regarding the course. 

I think the OSWA course did a great job in explaining every topics in the course and is enough to actually pass the exam. I find most of the topics feels easy enough to follow but maybe this is because I already did the PortSwigger Academy labs, so If you worked through the PortSwigger Academy labs that would greatly help you through this course.

The OSWA course also includes five challenge labs but one of these labs is actually used in one of the exercises so I would not really count it as a challenge lab, these labs was supposed to measure if you are ready for the exam. The four challenge labs does not have any walkthroughs so you will need to finish it yourself or ask for a nudge in Discord. I can definitely say that the five included labs are fun, and prepares you on what to expect in the exam.

To pass the exam the student needs 70 out of the 100 points, 10 points per flag. There is local.txt which is located in the admin panel, and proof.txt in the system itself obtainable via RCE.

## Exam Prep

I enrolled in this course at February 2022 and been studying on and off as I have a full time job. While going through the course I made sure to take notes of every commands and script that could be helpful for the exam, once i finished the course topics I started working on the challenge labs and creating a writeup for them in my notes, taking note of what commands worked and did not work etc. this proved helpful on exam time as I can just copy and paste commands and scripts from it making the whole exploitation faster which is critical as we only have a day to solve the boxes.

I also finished some proving grounds play/practice machines, just to improve my speed in enumerating boxes. It would have been easier if the filter function in proving grounds play/practice works so you can focus on boxes related to OSWA topics but at the time of my studying it is not working. Some of the most helpful boxes I found that actually covers the topics in OSWA are listed below:

- Dibble
- Muddy
- Noname
- Snookums
- Sumo
- FunboxeasyEnum
- Inclusiveness
- Shakabra
- Slort

## Exam Time

I booked my exam to be 12PM Auckland time, everything worked as intended. Before anything else I recommend carefully reading the instructions in the exam control panel, be sure to take screenshots of findings as mentioned in the instructions. We also needed to submit the local.txt and proof.txt flags in the exam control panel so I made sure to submit them as soon as I got them as we will lose connectivity to this control panel once our exam is finished.

My exam did not went as smoothly as I wanted to, I got stuck in my first machine for around an hour with nothing so I decided to moved on to my second box which I solved in under an hour, after that it's smooth sailing I was able to obtain eight flags at around 6:30pm. As soon as I submitted my 8th flag I decided to focus on checking if I have the proper screenshots for my report as I knew that I already have enough to pass the exam. I took quite a bit of breaks as well whenever the exploit I am trying is not working and I would say it really helped so I will definitely advice to take break whenever you need to!

After checking all my screenshots I tried to solve my first box again and was able to get another flag, unfortunately I was unable to get the last flag and just decided to sleep at around 10pm and wake up early. The next morning I just focussed on writing my report and making sure all my flags are correctly submitted.

## Report

Report writing was fairly easy as I already have the screenshots needed and I also prepared/edited the given Offsec template so I just copy pasted what ever info or screenshot is needed. Also needed to make sure that all the commands or exploit I used was included inside the pdf report in a text format and not image. the offsec official template can be found [here](https://help.offensive-security.com/hc/en-us/articles/4410105650964-OSWA-Exam-Guide#suggested-documentation-templates).

After writing the report and copy pasting a bunch of commands it is time to submit the report, Offensive security has a pretty strict procedure regarding their submission format. Make sure to read the guide properly [Submission Instructions](https://help.offensive-security.com/hc/en-us/articles/4410105650964-OSWA-Exam-Guide#section-3-submission-instructions). The only contents of your zip file should be your pdf report, also make sure that the file name is correct and follows the offsec format.

A day after submitting my report I went to the exam page of WEB-200 and to my surprise it says that I passed even though I have not received an email yet, after a couple of days I received the confirmation email from offensive security.

<kbd>![](/static/assets/images/certs/oswa/2022-08-28-23-31-19.png)</kbd>

## Tips

- While going through your course take notes! List down what commands did not work and which ones worked, take note of all the scripts etc. This will also help you regarding the speed problem as you can just copy paste commands and will just need to tweak it a little bit as needed.
- Practice in PG play/practice to improve your speed. Check out the boxes I listed above. While doing the listed boxes, take screenshots of every steps and try to note down eveything! This is a good habit to prepare for the exam as we needed proper screenshots for our flags to count.
- Take a break whenever you need to! taking a break helped me during the exam when I'm feeling stuck.
- Read the [Exam Guide](https://help.offensive-security.com/hc/en-us/articles/4410105650964-OSWA-Exam-Guide).
- Prepare your report template prior to the exam. This really helped me and made the whole reporting easier as I already have a plan on how to do my report.

All in all I would definitely recommend the OSWA certification for anyone who is just starting and would love to learn about web application testing. Good Luck!