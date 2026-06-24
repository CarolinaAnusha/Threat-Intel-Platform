import json
import csv
from io import StringIO

from PyPDF2 import PdfReader
from docx import Document


class FileParser:

    def parse(self, file):

        filename = file.filename.lower()

        if filename.endswith(".txt"):
            return file.file.read().decode("utf-8")

        if filename.endswith(".json"):
            content = json.load(file.file)
            return json.dumps(content)

        if filename.endswith(".csv"):
            content = file.file.read().decode("utf-8")

            reader = csv.reader(StringIO(content))

            rows = []

            for row in reader:
                rows.append(",".join(row))

            return "\n".join(rows)

        if filename.endswith(".pdf"):

            reader = PdfReader(file.file)

            text = ""

            for page in reader.pages:
                text += page.extract_text() or ""

            return text

        if filename.endswith(".docx"):

            doc = Document(file.file)

            return "\n".join(
                paragraph.text
                for paragraph in doc.paragraphs
            )

        raise ValueError("Unsupported file type")