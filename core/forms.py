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
        }from django import forms
from django.contrib.auth.models import User
from .models import RestroomReport, UserProfile


class RestroomReportForm(forms.ModelForm):
    class Meta:
        model = RestroomReport
        fields = ['location', 'category', 'description', 'photo', 'is_urgent']
        widgets = {
            'location': forms.Select(attrs={'class': 'form-select'}),
            'category': forms.Select(attrs={'class': 'form-select'}),
            'description': forms.Textarea(attrs={
                'class': 'form-control', 
                'rows': 4, 
                'placeholder': 'Provide specific details regarding the concern...'
            }),
            'photo': forms.FileInput(attrs={'class': 'form-control'}),
            'is_urgent': forms.CheckboxInput(attrs={'class': 'form-check-input', 'id': 'id_is_urgent'}),
        }


class StudentRegistrationForm(forms.ModelForm):
    first_name = forms.CharField(
        max_length=30, 
        required=True, 
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'First Name'})
    )
    last_name = forms.CharField(
        max_length=30, 
        required=True, 
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Last Name'})
    )
    email = forms.EmailField(
        required=True, 
        widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'School Email (@ua.edu.ph)'})
    )
    student_id = forms.CharField(
        max_length=50, 
        required=True, 
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Student ID Number (e.g. 2023-12345)'})
    )
    id_picture = forms.ImageField(
        required=True, 
        widget=forms.FileInput(attrs={'class': 'form-control', 'accept': 'image/*'})
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Password'})
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Confirm Password'})
    )

    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'email']
        widgets = {
            'username': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Username'}),
        }

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("This school email is already registered.")
        return email

    def clean_student_id(self):
        student_id = self.cleaned_data.get('student_id')
        if UserProfile.objects.filter(student_id=student_id).exists():
            raise forms.ValidationError("This Student ID number is already registered.")
        return student_id

    def clean_confirm_password(self):
        password = self.cleaned_data.get("password")
        confirm_password = self.cleaned_data.get("confirm_password")
        if password and confirm_password and password != confirm_password:
            raise forms.ValidationError("Passwords do not match.")
        return confirm_password