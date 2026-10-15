from django import forms


class QuantityForm(forms.Form):
    quantity = forms.IntegerField(min_value=1, max_value=99, initial=1)


class CheckoutForm(forms.Form):
    cart_id = forms.UUIDField(widget=forms.HiddenInput)
    name = forms.CharField(max_length=100, label='Your name')
    email = forms.EmailField(label='Email address')


class PaymentForm(forms.Form):
    token = forms.CharField(max_length=2048, widget=forms.HiddenInput)
    outcome = forms.ChoiceField(choices=[('approve', 'Simulate successful payment'), ('decline', 'Simulate declined payment')])
    card_number = forms.RegexField(
        regex=r'^4242 ?4242 ?4242 ?4242$', max_length=23,
        error_messages={'invalid': 'Use the fake test card 4242 4242 4242 4242.'})
    expiry = forms.RegexField(regex=r'^12/30$', max_length=5,
        error_messages={'invalid': 'Use the fake expiry 12/30.'})
    cvv = forms.RegexField(regex=r'^123$', max_length=3,
        error_messages={'invalid': 'Use the fake security code 123.'})
