from django.contrib.auth.models import User
from rest_framework import serializers
import bcrypt


#Defines the fields that get serialized/deserialized
from authentication.models import NetworkType, Vulnerability, Url


class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = ('url', 'username', 'email') # May change this to ModelSerializer?

    #Define how instances are created when calling serializer.save()
    def create_user(request):
        if request.method == 'POST':
            password = request.POST['password']
            email = request.POST['email']
            username = request.post['username']
            thehash = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt(10)),

            User.objects.create(
                email=email,
                username=username,
                password=thehash,
            )

    # Define how instances are updated when calling serializer.save()
    def update(self, instance, validated_data):
        """
        Update and return an existing `User` instance, given the validated data.
        """
        instance.password = validated_data.get('password', instance.kkk)
        instance.email = validated_data('email', instance.email)
        instance.username = validated_data('username', instance.username)
        instance.save
        return instance


class NetworkDevice(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = ('url', 'name', 'password')


class NetworkTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetworkType
        fields = ('id', 'network_type')

        def testing(self):
            test = 'test'


class VulnerabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Vulnerability
        fields = ('vulnerabilityId',
                  'host',
                  'port',
                  'protocol',
                  'name',
                  'technicalname',
                  'baseScore',
                  'baseVector',
                  'family',
                  'summary',
                  'impact',
                  'solution',
                  'solution_type',
                  'technicalDetails',
                  'threatRating',
                  'date')


class UrlInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = Url
        fields = ('urlName', 'urlDescription')



