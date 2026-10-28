from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import PasswordResetForm
from .models import RestroomReport, RestroomLocation, UserProfile


PRIMARY_CATEGORY_CHOICES = [
    ('', '-- Select Category --'),
    ('Plumbing', 'Plumbing'),
    ('Cleanliness', 'Cleanliness'),
    ('Supplies', 'Supplies'),
    ('Damaged Fixtures', 'Damaged Fixtures'),
    ('Other', 'Other'),
]


class RestroomReportForm(forms.ModelForm):
    category = forms.ChoiceField(
        choices=PRIMARY_CATEGORY_CHOICES,
        widget=forms.Select(attrs={
            'class': 'form-select form-control-water',
            'required': 'required'
        })
    )
    photo = forms.ImageField(
        required=True,
        widget=forms.FileInput(attrs={
            'class': 'form-control form-control-water',
            'accept': 'image/*',
            'id': 'report_photo_input',
            'required': 'required'
        }),
        help_text="Required photo evidence of the maintenance or cleanliness issue."
    )

    class Meta:
        model = RestroomReport
        fields = ['location', 'category', 'description', 'photo', 'is_urgent']
        widgets = {
            'location': forms.Select(attrs={
                'class': 'form-select form-control-water',
                'required': 'required'
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control form-control-water',
                'rows': 4,
                'placeholder': 'Provide specific details regarding the concern (e.g. leaking sink, no running water, broken lock)...',
                'required': 'required'
            }),
            'is_urgent': forms.CheckboxInput(attrs={
                'class': 'form-check-input',
                'id': 'id_is_urgent'
            }),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['location'].empty_label = "-- Select Restroom Location --"
        self.fields['location'].queryset = RestroomLocation.objects.all().order_by('building', 'floor', 'room_number')


class StudentRegistrationForm(forms.ModelForm):
    first_name = forms.CharField(
        max_length=30,
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-control form-control-water',
            'placeholder': 'First Name',
            'autocomplete': 'given-name'
        })
    )
    last_name = forms.CharField(
        max_length=30,
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-control form-control-water',
            'placeholder': 'Last Name',
            'autocomplete': 'family-name'
        })
    )
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            'class': 'form-control form-control-water',
            'placeholder': 'yourname@ua.edu.ph',
            'autocomplete': 'email'
        }),
        help_text="Must be an official institutional email (@ua.edu.ph)"
    )
    student_id = forms.CharField(
        max_length=50,
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-control form-control-water',
            'placeholder': 'Student ID Number (e.g. 2023-10023)'
        })
    )
    id_picture = forms.ImageField(
        required=True,
        widget=forms.FileInput(attrs={
            'class': 'form-control form-control-water',
            'accept': 'image/*',
            'id': 'student_id_picture_input'
        }),
        help_text="Upload a clear photo/scan of your Student ID for identity verification."
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control form-control-water',
            'placeholder': 'Create password (min 6 characters)'
        }),
        min_length=6
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control form-control-water',
            'placeholder': 'Re-enter password to confirm'
        })
    )

    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'email']
        widgets = {
            'username': forms.TextInput(attrs={
                'class': 'form-control form-control-water',
                'placeholder': 'Username (e.g. student.id or handle)',
                'autocomplete': 'username'
            }),
        }

    def clean_email(self):
        email = self.cleaned_data.get('email', '').strip().lower()
        if not email.endswith('@ua.edu.ph'):
            raise forms.ValidationError("Institutional verification error: Only official '@ua.edu.ph' email addresses are accepted.")
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("This school email is already registered. Please sign in or use password recovery.")
        return email

    def clean_student_id(self):
        student_id = self.cleaned_data.get('student_id', '').strip()
        if not student_id:
            raise forms.ValidationError("Student ID is required.")
        if UserProfile.objects.filter(student_id__iexact=student_id).exists():
            raise forms.ValidationError("This Student ID number is already registered in the system.")
        return student_id

    def clean_username(self):
        username = self.cleaned_data.get('username', '').strip()
        if User.objects.filter(username__iexact=username).exists():
            raise forms.ValidationError("This username is already taken. Please choose another.")
        return username

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        confirm_password = cleaned_data.get("confirm_password")
        if password and confirm_password and password != confirm_password:
            self.add_error("confirm_password", "Passwords do not match. Please ensure both fields are identical.")
        return cleaned_data


class InstitutionalPasswordResetForm(PasswordResetForm):
    email = forms.EmailField(
        label="Institutional Email",
        max_length=254,
        widget=forms.EmailInput(attrs={
            'class': 'form-control form-control-water',
            'placeholder': 'name@ua.edu.ph',
            'autocomplete': 'email'
        })
    )

    def clean_email(self):
        email = self.cleaned_data.get('email', '').strip().lower()
        if not email.endswith('@ua.edu.ph'):
            raise forms.ValidationError("Only institutional accounts ending with '@ua.edu.ph' can request password resets.")
        if not User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("No registered account found with this institutional email.")
        return email
