<a name="readme-top"></a>

<!-- PROJECT LOGO -->
<br />
<div align="center">
  <h3 align="center">Secure Communication System Simulation</h3>

  <p align="center">
    <a href="https://github.com/cgarcia156/My-Local-Database/issues">Report Bug</a>
    ·
    <a href="https://github.com/cgarcia156/My-Local-Database/issues">Request Feature</a>
  </p>
</div>



<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
    </li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project

This program simulates a secure communication system between two parties. The two parties have each other’s RSA public key.
Each of them holds his/her own RSA private key. Each party’s message (from a .txt file) is encrypted using AES before
sending it to another party. The AES key is encrypted using the receiver’s RSA public key and the encrypted AES key is sent
together with the encrypted message. A message authentication code is sent with the transmitted data. 

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Algorithms Used
* AES - AES/CBC/PKCS5Padding (256 bit key)
* RSA - RSA/ECB/PKCS1Padding (2048 bit key)
* MAC - HMACSHA256 (256 bit key)


### Built With

* Java (java.security, java.crypto)


<!-- GETTING STARTED -->
## Getting Started

Simply clone the repo to get your own local copy
  ```sh
  git clone https://github.com/cgarcia156/SecureCommunicationSystem.git
  ```
You can generate keys using KeyGeneration.java
<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- USAGE EXAMPLES -->
### Usage
#### Sender
You will need text files containing:
  <li> The public key of the person you want to send the message to </li>
  <li> The message you wish to send </li>
  <li> The initialization vector for AES </li>
  <li> The key for the MAC </li>
Note: The receiver will need to know the MAC key in advance.
</br>
</br>
<p> When running the program, you will be prompted to enter the names of these files. </p>

<div align-"left">
<img src="Images/Sender_Example.png" alt="Sender_Example" width="400" height="220">
</div>
<br>
When the program finishes, the data will be stored (in byte form) in “TransmittedData.txt”.


#### Receiver
You will need text files containing:
  <li> Your private key </li> 
  <li> The MAC key </li> 
  <li> The initialization vector for AES </li> 
  <br> 
When running the program, you will be prompted to enter the names of these files along
with a file for the output.
<div align-"left">
<img src="Images/Receiver_Example.png" alt="Receiver_Example" width="400" height="280">
</div>
<br>



<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- CONTACT -->
## Contact

Christian Garcia - christiangarcia.cg77@gmail.com

Project Link: [https://github.com/cgarcia156/SecureCommunicationSystem](https://github.com/cgarcia156/SecureCommunicationSystem)

<p align="right">(<a href="#readme-top">back to top</a>)</p>
