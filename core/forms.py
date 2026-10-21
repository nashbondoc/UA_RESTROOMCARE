from django import forms
from .models import RestroomReport

class RestroomReportForm(forms.ModelForm):
    class Meta:
        model = RestroomReport
        fields = ['location', 'category', 'description', 'photo', 'is_urgent']
        widgets = {
            'location': forms.Select(attrs={'class': 'form-select'}),
            'category': forms.Select(attrs={'class': 'form-select'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 4, 'placeholder': 'Provide specific details regarding the concern...'}),
            'photo': forms.FileInput(attrs={'class': 'form-control'}),
            'is_urgent': forms.CheckboxInput(attrs={'class': 'form-check-input', 'id': 'id_is_urgent'}),
        }