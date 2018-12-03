import { Injectable } from '@angular/core';
import {User} from '../Model/user';
import { HttpClient } from '@angular/common/http';
import {environment} from '../../environments/environment';

@Injectable({
  providedIn: 'root'
})
export class UserService {

  constructor(private http: HttpClient) { }

  register(user: User) {
    return this.http.post(environment.apiEndpoint + '/users/register', user);
  }

  update(userId: String, oldPassword: String, newPassword: String) {
    const obj = { oldPassword: oldPassword, newPassword: newPassword};
    return this.http.put(environment.apiEndpoint + '/users/' + userId, obj);
  }
}
