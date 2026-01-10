# --- TASK 2: Pseudonymization Script ---

# 1. Initial Data (Raw Data)
customers = [
    {"name": "Άννα", "surname": "Παπαδοπούλου", "email": "anna@example.com", "age": 28, "profession": "Ιατρός"},
    {"name": "Κώστας", "surname": "Νικολάου", "email": "kostas@example.com", "age": 35, "profession": "Μηχανικός Η/Υ"},
    {"name": "Ιωάννα", "surname": "Γεωργίου", "email": "ioanna@example.com", "age": 22, "profession": "Καθηγήτρια"}
]

# Lists to store the separated data
pseudonymized_data = []
mapping_table = []

# 2. Processing Loop (Technique: Counter)
# We use a simple counter (1, 2, 3...) to generate the User ID.
counter = 1

for person in customers:
    # Generate the Pseudonym
    user_id = f"USER{counter}"
    
    # A. Create the Mapping Table (Secret Key)
    # This stores the link between the ID and the Real Identity.
    mapping_table.append({
        "Pseudonym": user_id,
        "Real_Name": person["name"],
        "Real_Surname": person["surname"],
        "Real_Email": person["email"]
    })
    
    # B. Create the Pseudonymized Data (For the Partner)
    # This stores the ID and the data needed for analysis (Age, Profession).
    # Identifiers (Name, Email) are REMOVED.
    pseudonymized_data.append({
        "Pseudonym": user_id,
        "Age": person["age"],
        "Profession": person["profession"]
    })
    
    counter += 1

# 3. Output the Results
print("--- TABLE 1: PSEUDONYMIZED DATA (Sent to External Partner) ---")
print(f"{'Pseudonym':<10} | {'Age':<5} | {'Profession'}")
print("-" * 40)
for row in pseudonymized_data:
    print(f"{row['Pseudonym']:<10} | {row['Age']:<5} | {row['Profession']}")

print("\n" + "="*50 + "\n")

print("--- TABLE 2: MAPPING TABLE (Kept Securely internally) ---")
print(f"{'Pseudonym':<10} | {'Real_Email':<20} | {'Full Name'}")
print("-" * 50)
for row in mapping_table:
    print(f"{row['Pseudonym']:<10} | {row['Real_Email']:<20} | {row['Real_Name']} {row['Real_Surname']}")
