# Volos Vector Clock (VOLOSVC)
<pre>
     _________________________/\/\____________________________/\/\____/\/\____/\/\/\/\/\_
    _/\/\__/\/\____/\/\/\____/\/\______/\/\/\______/\/\/\/\__/\/\____/\/\__/\/\_________ 
   _/\/\__/\/\__/\/\__/\/\__/\/\____/\/\__/\/\__/\/\/\/\____/\/\____/\/\__/\/\_________  
  ___/\/\/\____/\/\__/\/\__/\/\____/\/\__/\/\________/\/\____/\/\/\/\____/\/\_________   
 _____/\________/\/\/\____/\/\/\____/\/\/\____/\/\/\/\________/\/\________/\/\/\/\/\_    
____________________________________________________________________________________     
</pre>

A lightweight, `HashMap`-based implementation of **Vector Clocks** for tracking partial ordering and detecting causality in distributed systems.
- by Keith Makan (KMSEC)

---

## 🚀 Features
* **Dynamic Node Tracking**: Uses a `HashMap` to allow nodes to join the system dynamically without pre-defining the cluster size.
* **Causality Comparison**: Built-in partial ordering to determine if events are *Succeeded by*, *Preceded by*, or *Concurrent with* others.
* **Custom Display**: Clean, readable string representation for logging and debugging.

## 📦 Installation

Add this to your `Cargo.toml` if you are splitting this into a library:

```toml
[package]
name = "vector_clock"
version = "0.1.0"
edition = "2021"

[dependencies]
# No external dependencies required for the core logic!

