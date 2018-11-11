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
    console.log(user);
    return this.http.post(environment.apiEndpoint + '/users/register', user);
  }

  update(user: User) {
    return this.http.put(environment.apiEndpoint + '/users' + user.id, user);
  }

  delete(id: number) {
    return this.http.delete(environment.apiEndpoint + '/users' + id);
  }
}
