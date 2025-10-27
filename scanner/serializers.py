# scanner/serializers.py
from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate
from .models import ScanResult
import json

# In your serializer
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email']  # ✅ Include ID

class ScanResultSerializer(serializers.ModelSerializer):
    open_ports = serializers.SerializerMethodField()
    sql_injection = serializers.SerializerMethodField()
    xss = serializers.SerializerMethodField()
    recommendations = serializers.SerializerMethodField()

    class Meta:
        model = ScanResult
        fields = "__all__"

    def get_open_ports(self, obj):
        if obj.open_ports:
            try:
                return obj.open_ports.split("\n")  # stored as newline string
            except Exception:
                return []
        return []

    def get_sql_injection(self, obj):
        if obj.sql_injection:
            try:
                return json.loads(obj.sql_injection)
            except Exception:
                return {"raw": obj.sql_injection}
        return None

    def get_xss(self, obj):
        if obj.xss:
            try:
                return json.loads(obj.xss)
            except Exception:
                return {"raw": obj.xss}
        return None

    def get_recommendations(self, obj):
        if obj.recommendations:
            return obj.recommendations.split("\n")  # return as list
        return []


# ✅ Signup Serializer (with duplicate email validation)
class SignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ["id", "email", "password"]

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value

    def create(self, validated_data):
        user = User.objects.create(
            username=validated_data["email"],  # use email as username
            email=validated_data["email"],
            password=make_password(validated_data["password"]),
        )
        return user


# ✅ Signin Serializer
class SigninSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get("email")
        password = data.get("password")

        # authenticate using username = email
        user = authenticate(username=email, password=password)
        if user is None:
            raise serializers.ValidationError("Invalid email or password")

        data["user"] = user
        return data

