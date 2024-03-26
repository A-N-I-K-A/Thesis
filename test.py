from odf import text, teletype
from odf.opendocument import OpenDocumentText


# Define the number of hospitals, nurses, and doctors
num_hospitals =16# A to Z
avg_nurses_per_hospital = 8
avg_doctors_per_hospital = 16

# Generate the list
hospital_list = []


# Example usage
file_path = '/home/anika/Desktop/Thesis/Data/attribute_list.odt'


def write_to_odt(file_path, content):
    # Create a new ODT document
    doc = OpenDocumentText()

    # Add a text paragraph to the document
    paragraph = text.P()
    paragraph.addText(content)
    doc.text.addElement(paragraph)

    # Save the document to a file
    doc.save(file_path)

for hospital_index in range(num_hospitals):
    hospital_label = f"H{chr(ord('A') + hospital_index)}"
    hospital_list.append(f"{hospital_label}")
    
for nurse_index in range(1, avg_nurses_per_hospital + 1):
        nurse_label = f"N{nurse_index}"
        hospital_list.append(f"{nurse_label}")

for doctor_index in range(1, avg_doctors_per_hospital + 1):
        doctor_label = f"D{doctor_index}"
        hospital_list.append(f"{doctor_label}")

# Print the result
content=""
for item in hospital_list:
    print(item)
    content+=item
    content+=","
    
write_to_odt(file_path, content)


