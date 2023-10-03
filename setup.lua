print("**STARTING SETUP**")

function env()
	os.execute("pip install virtualenv")
	os.execute("python -m venv new_env")
	os.execute("source new_env/bin/activate")
end

function requirement()
	os.execute("pip install scapy")
	os.execute("pip install paramiko")
end

print("---------------------")

env()
requirement()

print("**SETUP COMPLETED**")
print(" ")

os.execute("lua start.lua")

