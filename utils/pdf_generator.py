"""
PDF Report Generator
Converts Markdown forensic reports to professional PDF documents
"""

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak,
    Table, TableStyle, Image, KeepTogether
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.pdfgen import canvas
from datetime import datetime
import re
import io

class PDFReportGenerator:
    """
    Generates professional PDF reports from Markdown content
    """
    
    def __init__(self):
        """Initialize PDF generator with styles"""
        self.styles = getSampleStyleSheet()
        self._create_custom_styles()
    
    def _create_custom_styles(self):
        """Create custom paragraph styles for the report"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#00ff41'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        # Heading 1
        self.styles.add(ParagraphStyle(
            name='CustomHeading1',
            parent=self.styles['Heading1'],
            fontSize=18,
            textColor=colors.HexColor('#00ff41'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        ))
        # Heading 2
        self.styles.add(ParagraphStyle(
            name='CustomHeading2',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#00cc33'),
            spaceAfter=10,
            spaceBefore=10,
            fontName='Helvetica-Bold'
        ))
        # Heading 3
        self.styles.add(ParagraphStyle(
            name='CustomHeading3',
            parent=self.styles['Heading3'],
            fontSize=12,
            textColor=colors.HexColor('#009922'),
            spaceAfter=8,
            spaceBefore=8,
            fontName='Helvetica-Bold'
        ))
        # Body text
        self.styles.add(ParagraphStyle(
            name='CustomBody',
            parent=self.styles['BodyText'],
            fontSize=10,
            leading=14,
            alignment=TA_JUSTIFY,
            spaceAfter=6
        ))
        # Code/monospace (avoid redefining if exists)
        if 'Code' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='Code',
                parent=self.styles['BodyText'],
                fontSize=9,
                fontName='Courier',
                textColor=colors.HexColor('#333333'),
                backColor=colors.HexColor('#f4f4f4'),
                leftIndent=20,
                rightIndent=20,
                spaceAfter=6
            ))
        # Bullet list
        self.styles.add(ParagraphStyle(
            name='CustomBullet',
            parent=self.styles['BodyText'],
            fontSize=10,
            leftIndent=20,
            bulletIndent=10,
            spaceAfter=4
        ))
    
    def generate_pdf(self, markdown_text, filename="forensic_report.pdf"):
        """
        Generate PDF from Markdown text
        
        Args:
            markdown_text: Markdown formatted report text
            filename: Output PDF filename
            
        Returns:
            bytes: PDF file as bytes
        """
        # Create PDF buffer
        buffer = io.BytesIO()
        
        # Create PDF document
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )
        
        # Parse markdown and build story
        story = []
        story.extend(self._parse_markdown(markdown_text))
        
        # Build PDF
        doc.build(story, onFirstPage=self._add_header_footer, 
                  onLaterPages=self._add_header_footer)
        
        # Get PDF bytes
        pdf_bytes = buffer.getvalue()
        buffer.close()
        
        return pdf_bytes
    
    def _parse_markdown(self, markdown_text):
        """
        Parse Markdown text and convert to ReportLab flowables
        
        Args:
            markdown_text: Markdown formatted text
            
        Returns:
            list: List of ReportLab flowables
        """
        story = []
        lines = markdown_text.split('\n')
        
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            
            # Skip empty lines
            if not line:
                i += 1
                continue
            
            # Main title (# with emoji)
            if line.startswith('# 🔍'):
                text = self._clean_text(line[2:])
                story.append(Paragraph(text, self.styles['CustomTitle']))
                story.append(Spacer(1, 0.2*inch))
                i += 1
                continue
            
            # Heading 1 (##)
            if line.startswith('## '):
                text = self._clean_text(line[3:])
                story.append(Spacer(1, 0.15*inch))
                story.append(Paragraph(text, self.styles['CustomHeading1']))
                i += 1
                continue
            
            # Heading 2 (###)
            if line.startswith('### '):
                text = self._clean_text(line[4:])
                story.append(Paragraph(text, self.styles['CustomHeading2']))
                i += 1
                continue
            
            # Heading 3 (####)
            if line.startswith('#### '):
                text = self._clean_text(line[5:])
                story.append(Paragraph(text, self.styles['CustomHeading3']))
                i += 1
                continue
            
            # Horizontal rule
            if line.startswith('---'):
                story.append(Spacer(1, 0.1*inch))
                story.append(Table([['']], colWidths=[6.5*inch], 
                           style=[('LINEABOVE', (0,0), (-1,0), 2, colors.HexColor('#00ff41'))]))
                story.append(Spacer(1, 0.1*inch))
                i += 1
                continue
            
            # Bullet list
            if line.startswith('- ') or line.startswith('* '):
                bullet_items = []
                while i < len(lines) and (lines[i].strip().startswith('- ') or 
                                         lines[i].strip().startswith('* ')):
                    item_text = self._clean_text(lines[i].strip()[2:])
                    bullet_items.append(Paragraph(f"• {item_text}", 
                                                  self.styles['CustomBullet']))
                    i += 1
                story.extend(bullet_items)
                story.append(Spacer(1, 0.1*inch))
                continue
            
            # Numbered list
            if re.match(r'^\d+\.', line):
                list_items = []
                while i < len(lines) and re.match(r'^\d+\.', lines[i].strip()):
                    match = re.match(r'^(\d+)\.\s*(.*)', lines[i].strip())
                    if match:
                        num, item_text = match.groups()
                        item_text = self._clean_text(item_text)
                        list_items.append(Paragraph(f"{num}. {item_text}", 
                                                   self.styles['CustomBullet']))
                    i += 1
                story.extend(list_items)
                story.append(Spacer(1, 0.1*inch))
                continue
            
            # Code block (backticks)
            if '`' in line:
                text = self._clean_text(line)
                story.append(Paragraph(text, self.styles['Code']))
                i += 1
                continue
            
            # Bold/emphasis patterns
            if '**' in line or '*' in line:
                text = self._process_formatting(line)
                story.append(Paragraph(text, self.styles['CustomBody']))
                i += 1
                continue
            
            # Regular paragraph
            text = self._clean_text(line)
            if text:
                story.append(Paragraph(text, self.styles['CustomBody']))
            
            i += 1
        
        return story
    
    def _clean_text(self, text):
        """
        Clean and escape text for ReportLab
        
        Args:
            text: Raw text
            
        Returns:
            str: Cleaned text
        """
        # Remove markdown formatting
        text = re.sub(r'\*\*\*(.+?)\*\*\*', r'<b><i>\1</i></b>', text)  # Bold italic
        text = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)  # Bold
        text = re.sub(r'\*(.+?)\*', r'<i>\1</i>', text)  # Italic
        # Remove code font replacement to avoid PDF font errors
        text = re.sub(r'`(.+?)`', r'\1', text)  # Inline code as plain text
        
        # Remove emojis and special characters that might cause issues
        text = re.sub(r'[🔍📊📋🔬⏱️📁🚩🎯💡📎📝⚠️✅❌🚨🔒🔐🛡️📞🔗↔️📤💥🌐]', '', text)
        
        # Escape special XML characters
        text = text.replace('&', '&amp;')
        text = text.replace('<', '&lt;').replace('>', '&gt;')
        
        # Restore HTML tags we added
        text = text.replace('&lt;b&gt;', '<b>').replace('&lt;/b&gt;', '</b>')
        text = text.replace('&lt;i&gt;', '<i>').replace('&lt;/i&gt;', '</i>')
        text = text.replace('&lt;font', '<font').replace('&lt;/font&gt;', '</font>')
        
        return text
    
    def _process_formatting(self, text):
        """Process markdown formatting"""
        return self._clean_text(text)
    
    def _add_header_footer(self, canvas, doc):
        """
        Add header and footer to each page
        
        Args:
            canvas: ReportLab canvas
            doc: Document object
        """
        canvas.saveState()
        
        # Header
        canvas.setFont('Helvetica-Bold', 8)
        canvas.setFillColorRGB(0, 1, 0.25)  # Green color
        canvas.drawString(72, letter[1] - 50, "CYBER FORENSIC INVESTIGATION REPORT")
        canvas.drawRightString(letter[0] - 72, letter[1] - 50, 
                              f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        
        # Footer
        canvas.setFont('Helvetica', 8)
        canvas.setFillColorRGB(0.5, 0.5, 0.5)
        canvas.drawCentredString(letter[0]/2, 30, f"Page {doc.page}")
        canvas.drawString(72, 30, "CONFIDENTIAL")
        canvas.drawRightString(letter[0] - 72, 30, "AI-Based Forensics Framework v1.0.0")
        
        canvas.restoreState()


def generate_pdf_report(markdown_text, filename="forensic_report.pdf"):
    """
    Convenience function to generate PDF report
    
    Args:
        markdown_text: Markdown formatted report
        filename: Output filename
        
    Returns:
        bytes: PDF file as bytes
    """
    generator = PDFReportGenerator()
    return generator.generate_pdf(markdown_text, filename)