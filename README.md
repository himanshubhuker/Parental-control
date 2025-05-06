# NetGuardian - Parental Control System

## Overview

NetGuardian is a comprehensive parental control application that empowers parents to monitor, manage, and control their child's device activity in real time. With features like website blocking, live screenshots, anomaly detection, and more, NetGuardian helps ensure a safe and productive digital environment for children.

---

## Features

- **Website Blocking/Unblocking:** Instantly block or unblock specific websites on the child's device.
- **View Blocked Sites:** Display and manage a list of all currently blocked websites.
- **Monitor Running Applications:** View real-time lists of apps/processes running on the child's device.
- **Screen Lock:** Remotely lock the child's device screen for immediate intervention.
- **Live Screenshot:** Capture and view the current screen of the child's device.
- **Anomaly Detection:** Receive alerts if the child tries to access blocked sites or performs suspicious activities.
- **Chat:** Send instant messages to the child's device.
- **Time Filters:** Set time-based restrictions for specific websites.

---

## Technical Requirements

- **Python Version:** 3.x
- **Libraries:**  
  - `tkinter` (for GUI)
  - `Pillow` (for image processing)
  - `socket` (for network communication)
  - `threading`, `os`, `base64`, `datetime`, `io` (standard libraries)
- **Files/Folders Needed:**
  - `parent_agent.py` (Parent Controller GUI)
  - `logs.txt` (Log file for monitoring activity and anomalies)
  - `screenshots/` (Directory to save captured screenshots; created automatically)
  - `requirements.txt` (for easy dependency installation)
- **Network:**  
  - Both parent and child devices must be on the same network or have appropriate port forwarding.
  - Default communication port: `5500` (configurable).

---

## File Requirements & Usage

### 1. **Screenshots**
- **Directory:** `screenshots/`
- **Purpose:** Stores all screenshots captured from the child's device.
- **How to Use:**  
  - Click the "Take Screenshot" button in the GUI.
  - The screenshot will be saved in the `screenshots/` folder with a timestamped filename.
  - The latest screenshot is also previewed in the GUI.

### 2. **Blocked Sites**
- **How to Block a Site:**
  - Enter the website URL in the "Block Site" field and click "Block".
  - The site will be added to the blocked list and enforced on the child's device.
- **How to Unblock a Site:**
  - Select the site from the blocked sites list in the GUI and click "Unblock".
- **How to View Blocked Sites:**
  - The blocked sites tab in the GUI displays all currently blocked websites.
  - Click "Refresh" to update the list.

### 3. **Logs**
- **File:** `logs.txt`
- **Purpose:** Records all commands, anomalies, and significant events.
- **Sample Log Entries:**




- **How to Use:**
- Open `logs.txt` to review past actions, anomalies, and system events.

---

## Setup & Usage Steps

1. **Clone the Repository**





2. **Install Dependencies**


PIP INSTALL -r requirements



3. **Configure the Parent Controller**
- Open `parent_agent.py`.
- Set `CHILD_IP` to the IP address of the child's device.
- Set `PORT` if different from the default `5500`.

4. **Run the Child Agent**
- Ensure the child agent/server is running on the child's device (implementation not included here).

5. **Run the Parent Controller**



python parent_agent.py



6. **Using the GUI**
- **Block/Unblock Sites:** Use the Blocked Sites tab.
- **Take Screenshots:** Use the "Take Screenshot" button; images appear in the preview and are saved in `screenshots/`.
- **Monitor Apps:** Use the "Get Running Apps" command.
- **Lock Screen:** Use the "Lock Screen" action.
- **View Logs:** Check `logs.txt` for all activity.
- **Anomaly Alerts:** Pop-up alerts and log entries will notify you of suspicious activity.

---


---

## License

MIT License

---

> **Need help or want to contribute?**  
> Open an issue or start a discussion on the GitHub repository!

