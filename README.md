# 🔐 Secure Multi-Client Chat Server in C

## **Overview**
This is a **secure, concurrent chat server** implemented in **C**, which allows multiple clients to communicate via **end-to-end encrypted messages** using **OpenSSL (TLS encryption)**. It utilizes **OpenMP for concurrent client handling** on the server and **POSIX threads (pthreads) for asynchronous message handling** on the client.

This project demonstrates **secure communication, multi-threading, and parallel processing**, making it a **scalable** and **highly secure** chat system.

---

## **📌 Features**
✅ **End-to-End Secure Communication** – Messages between clients are **TLS-encrypted using OpenSSL**.  
✅ **Multi-Client Support** – The server **handles multiple clients concurrently** using **OpenMP**.  
✅ **Real-Time Messaging** – Clients can **send private or broadcast messages** in real time.  
✅ **Asynchronous I/O** – Client uses **POSIX threads** to send and receive messages **simultaneously**.  
✅ **Logging & Error Handling** – The server logs **all events**, including client connections, messages, and errors.  
✅ **Graceful Shutdown** – The server handles **SIGINT (Ctrl+C) gracefully**, ensuring **all connections close properly**.  

---

## **📌 Technologies Used**
🔹 **C Programming** – Core language for the server and client.  
🔹 **OpenSSL** – For **TLS encryption**, ensuring secure communication.  
🔹 **Sockets Programming** – Using **TCP/IP** for network communication.  
🔹 **OpenMP** – To handle multiple client connections **concurrently**.  
🔹 **POSIX Threads (pthreads)** – For **asynchronous** message handling on the client.  
🔹 **Git & GitHub** – Version control and collaboration.

---

## **📌 Project Setup & Installation**

Follow these steps to set up and run the chat server and client:

### **1️⃣ Install Required Dependencies**
Ensure you have OpenSSL and GCC installed:

#### **For Debian/Ubuntu:**
```sh
sudo apt update
sudo apt install gcc make libssl-dev
