##                      PLASMA PULSAR

####             CVE-2017-8422, CVE-2017-8849


This document describes a generic root exploit against kde.

The exploit is achieved by abusing a logic flaw within
the `KAuth` framework which is present in __kde4__ _(org.kde.auth)_ and __kde5__
_(org.kde.kf5auth)_. It is possible to spoof what `KAuth` calls
callerID's which are indeed _D-Bus_ unique names of the sender of a _D-Bus_
message.
Exploitation requires a helper which is doing some privileged work
as root. __Kde__ ships quite some of them, but for this writeup I chose the
_smb4k_ helper because it contains another vulnerability that makes
exploitation a lot easier; but in general any `KAuth` privileged helper code
can be triggered by users with arbitrary arguments which leads to
LPE on default __kde__ installations.

I will describe the overall problem by walking through the _smb4k_ code and
explain which _D-Bus_ functions are called and how a particular _smb4k_ bug maps
into the bigger picture of the `KAuth` flaw.

Theres a problem with _smb4k_ using the `KAuth` framework
and trusting all the arguments passed to the helper:

```C++
ActionReply Smb4KMountHelper::mount(const QVariantMap &args)
{

...

command << args["mh_command"].toString();
command << args["mh_unc"].toString();
command << args["mh_mountpoint"].toString();
command << args["mh_options"].toStringList();

...

proc.setProgram(command);
// Run the mount process.
proc.start();
...
}
```

This code is running as root, triggered via _D-Bus_ activation by _smb4k_ GUI
code running as user, and the `args` supplied by the user, via:

```C++
void Smb4KMountJob::slotStartMount()
{
...

 Action::executeActions(actions, NULL, "net.sourceforge.smb4k.mounthelper");
...
}
```

after filling `actions` (theres only one) with the proper Name
`net.sourceforge.smb4k.mounthelper.mount` and HelperID
`net.sourceforge.smb4k.mounthelper` in order to trigger _D-Bus_ activation as
well as the argument dictionary which contains the `mh_command` etc.
key/value pairs. Its calling the list-version of `Action::executeAction()`
[note the trailing 's'] with a one-element list, but that doesn't matter.
The important thing here is that the arguments are created by code
running as user - potentially containing evil input - and are evaluated
by the helper program running as root.

The above call ends at `DBusHelperProxy::executeAction()`, still at callers
side. This function translates it into a _D-Bus_ method call which is
finally running privileged and has the following interface:

```XML
<interface name="org.kde.kf5auth">
...
    <method name="performAction" >
        <arg name="action" type="s" direction="in" />
        <arg name="callerID" type="ay" direction="in" />
        <arg name="arguments" type="ay" direction="in" />
        <arg name="r" type="ay" direction="out" />
    </method>
...
</interface>
```

Unlike the root helpers _D-Bus_ interfaces itself, which are not
accessible as user, the `KAuth`  _D-Bus_ interface `org.kde.kf5auth` is:

```XML
<busconfig>
  <policy context="default">
    <allow send_interface="org.kde.kf5auth"/>
    <allow receive_sender="org.kde.kf5auth"/>
    <allow receive_interface="org.kde.kf5auth"/>
  </policy>
</busconfig>
```

The code for actually doing the call from user to root is this:

```C++
void DBusHelperProxy::executeAction(const QString &action,
     const QString &helperID, const QVariantMap &arguments)
{
...

QDBusMessage::createMethodCall(helperID, QLatin1String("/"),
   QLatin1String("org.kde.kf5auth"), QLatin1String("performAction"));

QList<QVariant> args;
args << action << BackendsManager::authBackend()->callerID() << blob;
message.setArguments(args);

m_actionsInProgress.push_back(action);

QDBusPendingCall pendingCall = m_busConnection.asyncCall(message);

...
}
```

This code is invoking the `performAction()` _D-Bus_ method, passing along the
user supplied `arguments` dictionary, in our _smb4k_ case containing the
handcrafted evil `mh_command` key, amongst others key/value pairs.

There are two problems:

The `KAuth` frameworks `performAction()` method is passed the `callerID` by the
user and the method is invokable by the user. This allows to mask as any
caller, bypassing any _polkit_ checks that may happen later in the `KAuth`
polkit backend via calls into

```C++
PolicyKitBackend::isCallerAuthorized(const QString &action,
                                     QByteArray callerID)
```

The second problem is _smb4k_ trusting the arguments that are passed from the
user and which are forwarded by the `KAuth` _D-Bus_ service running as root to
the mount helper _D-Bus_ service which is also running as root but not allowed
to be contacted by users.
Thats a logical flaw. It was probably not intented that users invoke
`performAction()` themself, using it as a proxy into _D-Bus_ services and
faking caller IDs en-passant. The `callerID` usually looks like `:1.123`
and is a _D-Bus_ unique name that maps to the sender of the message.
You can think of it like the source address of an IP packet.
This ID should be obtained via a _D-Bus_ function while the message is
arriving, so it can actually be trusted and used as a subject for _polkit_
authorizations when using `systembus-name` subjects. Allowing callers to
arbitrarily choosing values for this ID is taking down the whole idea
of authentication and authorization.

I made an exploit for _smb4k_ that works on _openSUSE Leap 42.2_ thats using
the `org.kde.auth` interface (rather than `org.kde.kf5auth`) but both
interfaces share the same problems. The exploit also works on the latest
_Fedora26 Alpha_ kde spin with _SELinux_ in enforcing mode. In order to test
the `callerID` spoofing, I "protected" the _smb4k_ helper code via `auth_admin`
polkit settings and tried mounting SMB shares via _smb4k_ GUI. This asked for
the root password, as its expected. The exploit however still works, as its
spoofing the `callerID` to be _D-Bus_ itself and the request is taken as legit,
requiring no root password.


![screenshot](https://github.com/stealth/plasmapulsar/blob/master/smb0k.jpg)

