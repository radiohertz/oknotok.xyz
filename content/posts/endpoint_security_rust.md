+++
title = "Apple's Endpoint Security Framework using Rust"
date = 2023-10-20T12:01:23+05:30
draft = true
tags = ['rust', 'osx', 'macos', 'endpoint security']
+++

*This blog was originally written for my employer. You can find the original [here](https://blog.subcom.tech/).*

*You can get the full source of the program on [codeberg](https://codeberg.org/evsky/ssh-notify).*

# Preface

This is a short tutorial using Apple's [Endpoint Security](https://developer.apple.com/documentation/endpointsecurity) Framework in Rust to build security applications.

We will build a small observability application that sends a notification to the desktop everytime someone SSH's into a machine that is running the application. 


# What is Endpoint Security? 

Endpoint Security is an Apple Framework to monitor system events for potentially suspicious activity. 

Endpoint Security clients can listen to various events, such as file system, processes, signals, etc. 
Check the official [Apple documentation](https://developer.apple.com/documentation/endpointsecurity/es_event_type_t) for a list of all the events you can listen to.

# The Program

*technical requirements*

- Rust compiler with version 1.65.0+
- MacOS Version 13.0+

**NOTE:**
Since programs that use Endpoint Security are special, you have to disable [System Integrity Protection](https://support.intego.com/hc/en-us/articles/115003523252-How-to-Disable-System-Integrity-Protection-SIP-) to run unsigned ES applications. 

Create a new project using cargo
```sh
cargo new ssh-notify
cd ssh-notify
```

We will be making use of the crates: 
- [endpoint-sec](https://crates.io/crates/endpoint-sec) : Rust bindings for the Endpoint Security C API.
- [notify-rust](https://crates.io/crates/notify-rust): Send notifications to the desktop.

Add these deps to your `Cargo.toml`
```toml
[dependencies]
endpoint-sec =  { version = "0.3.0", features = ["macos_13_0_0"] }
notify-rust = "4.9.0"
```


in `src/main.rs`, add the following imports

```rs
use endpoint_sec::{sys::es_event_type_t, Client, Event};
use notify_rust::Notification;
```

Now, we'll create an endpoint security client and subscribe to the events we require.

```rs
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = Client::new(|client, message| {})?;
    client.subscribe(&[
        es_event_type_t::ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN,
        es_event_type_t::ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT,
    ])?;

    Ok(())
}
```

We first create an ES client and pass it a closure. The closure gets the client itself and the message as an argument. The message contains all the metadata about the event that has happened.

We then subscribe to the events `ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN` and `ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT` as we are listening for the SSH events.


Next, we'll fill out the body of the closure passed to `Client::new`
```rs
let mut client = Client::new(|client, message| match message.event() {
    Some(Event::NotifyOpensshLogin(login_info)) => {
        println!("SSH Login: {login_info:#?}")
    }
    Some(Event::NotifyOpensshLogout(logout_info)) => {
        println!("SSH Login: {logout_info:#?}")
    }
    _ => {}
})?;

```

Since we only care about SSH login and logout events, we match those two events and log the event metadata to stdout.

Now, we can run the program but before that we have to do some codesigning since it is necessary for an ES app.

Create a file called `Extension.entitlements` and add these contents.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.developer.endpoint-security.client</key>
	<true/>
</dict>
</plist>
```

we can now build and codesign the executable with the entitlement
```console
idipot@mini ssh-notify % cargo build
   Compiling ssh-notify v0.1.0 (/Users/idipot/ssh-notify)
    Finished dev [unoptimized + debuginfo] target(s) in 0.92s

idipot@mini ssh-notify % codesign --entitlements Extension.entitlements --force -s - ./target/debug/ssh-notify
./target/debug/ssh-notify: replacing existing signature

```

We can finally run the program (don't forget to run the program as sudo). In a new terminal, SSH into your machine, and you should see the events being logged.

```console
idipot@mini ssh-notify % sudo ./target/debug/ssh-notify
Password:
SSH Login: EventOpensshLogin {
    success: false,
    result_type: es_openssh_login_result_type_t::ES_OPENSSH_AUTH_FAIL_PUBKEY(6),
    source_address_type: es_address_type_t::ES_ADDRESS_TYPE_IPV4(1),
    source_address: "192.168.0.121",
    username: "idipot",
    has_uid: true,
    uid: Some(
        501,
    ),
}
SSH Login: EventOpensshLogin {
    success: true,
    result_type: es_openssh_login_result_type_t::ES_OPENSSH_AUTH_SUCCESS(2),
    source_address_type: es_address_type_t::ES_ADDRESS_TYPE_IPV4(1),
    source_address: "192.168.0.121",
    username: "idipot",
    has_uid: true,
    uid: Some(
        501,
    ),
}
SSH Login: EventOpensshLogout {
    source_address_type: es_address_type_t::ES_ADDRESS_TYPE_IPV4(1),
    source_address: "192.168.0.121",
    username: "idipot",
    uid: 501,
}
```

Yay, we got events!!!

Now, instead of just logging the events we'll update our message handler to send a notification to the desktop using the `notify-rust` crate.

```rs
let mut client = Client::new(|client, message| match message.event() {
    Some(Event::NotifyOpensshLogin(login_info)) => {
        if login_info.success() {
            if let Err(e) = Notification::new()
                .summary("SSH Event")
                .body(&format!(
                    "{:?} logged into your PC from {:?}.",
                    login_info.username(),
                    login_info.source_address()
                ))
                .show()
            {
                println!("Failed to send notification: {e}");
            }
        }
    }
    Some(Event::NotifyOpensshLogout(logout_info)) => {
        if let Err(e) = Notification::new()
            .summary("SSH Event")
            .body(&format!(
                "{:?} logged out from your PC.",
                logout_info.username(),
            ))
            .show()
        {
            println!("Failed to send notification: {e}");
        }
    }
    _ => {}
})?;
```

You can rebuild the program, codesign it, run the program, and try ssh-ing. You should see notifications everytime there is a SSH login or logout.

![Login Notification](/es_rust1/login.png)

![Logout Notification](/es_rust1/logout.png)


YAY, WE GET OUR NOTIFICATIONS!!!

Now you can wish to extend this however you want; the important thing is to have fun and build security applications using the framework.

# Where to go from here?

Right now, the way we are codesigning the app is not ready for production use. 

Getting our endpoint security application production-ready is a bit of a hassle as Apple requires that we request for the Endpoint Security entitlement. You can apply for the entitlement [here](https://developer.apple.com/contact/request/system-extension/).

Once your developer account is approved for Endpoint Security entitlement, you can generate a provision profile with the entitlement enabled. You can then use the profile to sign your application.

This whole process is a bit scary and lacks documentation if you do not use xcode. I might do another blog showing how to do all this in the future.

The Future blog will contain the following information:

- Build an Endpoint Security daemon in Rust.
- Generate a Provision Profile for the Application. 
- Sign the application using the provision profile for distribution. 
